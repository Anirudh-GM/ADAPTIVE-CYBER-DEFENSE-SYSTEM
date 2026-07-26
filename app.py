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
import json
import re
import socket
import ssl
import subprocess
import platform
import functools
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
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# MODULE 0: MAC VENDOR / OUI LOOKUP
# ─────────────────────────────────────────────────────────────────

def mac_vendor(mac):
    """Look up the manufacturer of a MAC address using the local OUI table."""
    if not mac:
        return None
    prefix = mac.upper()[:8]  # "AA:BB:CC"
    return MOBILE_OUI_PREFIXES.get(prefix)


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

@functools.lru_cache(maxsize=128)
def lookup_cves_nvd(version_string):
    """
    Query the public NVD REST API for CVEs matching a free-text keyword
    (the parsed service/version string). Cached so we don't repeat the
    same network call during one session. Returns a list of dicts:
    [{'id', 'cvss', 'summary', 'fix_version'}] — fix_version is left None
    here since NVD doesn't structure that field; we surface the advisory
    text instead and let the SME's IT team confirm the patched version.
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
                "summary": summary[:200],
                "fix_version": None,
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
    """Fallback lookup against the small built-in historical CVE table."""
    product, detected_version = split_product_version(version_string)
    if not product or not detected_version:
        return []
    for key, cves in OFFLINE_CVE_FALLBACK.items():
        fallback_product, fallback_version = split_product_version(key)
        if (fallback_product == product and fallback_version == detected_version):
            return cves
    return []


def get_real_cves(service, version_string):
    """
    Try live NVD lookup first; fall back to the offline table; fall back
    further to nothing (caller then uses the generic baseline risk).
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
    if ttl is None:
        return 'unknown'
    if 110 <= ttl <= 130:
        return 'windows'
    if 55 <= ttl <= 75:
        return 'linux'
    if 240 <= ttl <= 260:
        return 'macos'
    return 'unknown'


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


def identify_device_type(hostname, os_type, is_mobile, services, mac=None):
    if is_tablet_device(hostname):
        return "Tablet"
    if is_mobile:
        return "Mobile Phone"

    hl = (hostname or '').lower()
    if any(h in hl for h in ['router', 'gateway', 'modem', 'ap-', 'wifi', 'fritz', 'tplink', 'netgear', 'asus']):
        return "Router/Gateway"
    if any(s in services for s in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        return "Database Server"
    # SMB/RPC and a local development HTTP service are common on Windows
    # workstations. Do not present that evidence as a certain server role.
    if os_type == 'windows' and not any(s in services for s in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        return "Windows Workstation"
    if any(s in services for s in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt', 'SSH', 'RDP', 'DNS', 'SMB']):
        return "Server"
    if os_type == 'macos':
        return "Mac"
    if os_type in ('windows', 'linux'):
        return "Computer"
    return "Network Device"


def build_risk_profile(open_ports, cve_findings, criticality):
    """Create an explainable 0-100 asset-risk estimate.

    This is a prioritisation score, not a claim that a host is compromised.
    Confirmed CVEs dominate the score; exposed services and asset importance
    raise priority only moderately when no CVE is confirmed.
    """
    sensitive_ports = {21, 23, 135, 139, 445, 3306, 3389, 5432, 5900, 6379, 27017}
    exposed_sensitive = sorted(set(open_ports) & sensitive_ports)
    max_cvss = max((float(c.get('cvss', 0)) for c in cve_findings), default=0.0)
    exposure_points = min(18, len(open_ports) * 2) + min(16, len(exposed_sensitive) * 5)
    criticality_points = max(0, criticality - 1) * 3
    if max_cvss:
        score = min(100, round(max_cvss * 7 + exposure_points + criticality_points))
        basis = "confirmed CVE plus exposure"
    else:
        score = min(49, round(8 + exposure_points + criticality_points))
        basis = "exposure only — no confirmed CVE"
    severity = "Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 35 else "Low"
    return {
        'score': score, 'severity': severity, 'basis': basis,
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
    Build the real, per-host security assessment:
      - For each open service, try to pull real CVEs via NVD/offline table
        using the detected version string.
      - If no version-specific CVE is found, fall back to the generic
        baseline exposure risk for that service type.
      - Always produce a SPECIFIC fix string naming the host, version, and
        (when available) the exact CVE + patched version.
    """
    version_map = version_map or {}
    weaknesses, access_vectors, fixes, cve_findings = [], [], [], []
    base_vuln = 0.20
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
            risk = min(0.98, top['cvss'] / 10.0)
            base_vuln = max(base_vuln, risk)
            cve_findings.append({
                'service': svc, 'port': port, 'version': version_str,
                'cve_id': top['id'], 'cvss': top['cvss'],
                'summary': top['summary'], 'fix_version': top.get('fix_version'),
                'source': source,
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
            risk = SERVICE_BASELINE_RISK.get(svc, 0.4)
            base_vuln = max(base_vuln, risk)
            label = f"Exposed {svc}{(' ' + version_str) if version_str else ''} (port {port}) — no version-specific CVE found, baseline exposure risk"
            if label not in weaknesses:
                weaknesses.append(label)
            mitre = SERVICE_MITRE.get(svc, ('T1190', 'Exploit Public-Facing Application'))
            access_vectors.append(mitre[1])
            generic_fix = GENERIC_FIXES.get(svc, f'Restrict access to {svc} and keep it patched')
            fix_text = f"{generic_fix} (host: {ip or 'this host'}, port {port})"
            if fix_text not in fixes:
                fixes.append(fix_text)

    if device_type in ('Mobile Phone', 'Tablet'):
        base_vuln = max(base_vuln, 0.38)
        weaknesses.append('Mobile device on LAN — phishing / credential-theft foothold; often unmanaged by IT')
        fixes.append(f'Move {ip or "this device"} to a guest/BYOD VLAN isolated from servers; enforce MDM and screen-lock policy if company-owned')

    if os_type == 'windows' and 'SMB' in services:
        base_vuln = max(base_vuln, 0.62)
        if 'Windows host with SMB exposed — domain credential relay risk' not in weaknesses:
            weaknesses.append('Windows host with SMB exposed — domain credential relay risk')
            fixes.append(f'Enable Windows Defender Firewall on {ip or "this host"}; restrict SMB to the file-server subnet only')

    if role == 'Database':
        base_vuln = max(base_vuln, 0.70)
        weaknesses.append('Database tier reachable from LAN — high-value target')
        fixes.append(f'Place {ip or "this database"} on an isolated VLAN; allow only the specific app-server IPs that need it')

    if not weaknesses:
        weaknesses.append('Host reachable on network — baseline lateral movement target')
        fixes.append(f'Apply OS patches on {ip or "this host"}; enable host firewall; remove unused services')

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

    risk_profile = build_risk_profile(open_ports, cve_findings, criticality)
    return {
        # Kept for simulation compatibility; the user-facing value is now
        # labelled "Risk score" and explained through risk_profile.
        'vulnerability': round(risk_profile['score'] / 100, 2),
        'exposure_level': round(min(base_vuln, 0.98), 2),
        'risk_profile': risk_profile,
        'weaknesses': weaknesses,
        'access_vectors': access_vectors,
        'fixes': fixes,
        'criticality': criticality,
        'cve_findings': cve_findings,
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
    if device_type in ('Mobile Phone', 'Tablet'):
        return 'Workstation'
    if os_type in ['windows', 'linux', 'macos']:
        return 'Workstation'
    return 'Workstation'


def scan_network(base_ip=None, limit=254, progress_cb=None):
    """
    Full discovery pipeline: ping sweep -> ARP/MAC -> hostname -> port scan
    -> banner grab -> per-host record. progress_cb(done, total) is called
    as hosts are enriched, for a live progress bar in the UI.
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

    arp_map = read_arp_map(subnet_prefix)
    candidate_ips = {ip for ip in (set(ping_results) | set(arp_map)) if ip_in_subnet(ip, base_ip)}

    total = len(candidate_ips)

    def enrich_device(ip):
        # NOTE: this runs inside a worker thread. Never call Streamlit UI
        # functions (st.*, or a progress_cb that wraps them) from in here —
        # Streamlit only allows UI updates from the main script thread and
        # will raise NoSessionContext otherwise. Progress is reported back
        # in the main-thread as_completed() loop below instead.
        ttl = ping_results.get(ip)
        mac = arp_map.get(ip)
        if not mac and system == "Windows":
            mac = lookup_mac_windows(ip)

        hostname = resolve_hostname(ip)
        os_type = ttl_to_os(ttl)
        is_mobile = is_mobile_device(hostname, ip, mac)
        open_ports = scan_ports(ip, SCAN_PORTS) if ip in ping_results else []
        services, version_map, banner_map = detect_services_and_versions(ip, open_ports)
        device_type = identify_device_type(hostname, os_type, is_mobile, services, mac)
        display_name = format_device_display_name(hostname, device_type, ip)
        vendor = mac_vendor(mac)

        return {
            'hostname': hostname, 'os': os_type, 'is_mobile': is_mobile, 'mac': mac,
            'mac_vendor': vendor, 'open_ports': open_ports, 'services': services,
            'version_map': version_map, 'banner_map': banner_map,
            'device_type': device_type, 'display_name': display_name,
        }

    devices = {}
    done = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(enrich_device, ip): ip for ip in sorted(candidate_ips)}
        for future in as_completed(futures):
            ip = futures[future]
            devices[ip] = future.result()
            done += 1
            if progress_cb:
                # Safe: this loop runs on the main thread, not a worker thread.
                progress_cb(done, total)

    return [
        (ip, d['hostname'], d['os'], d['is_mobile'], d['mac'], d['mac_vendor'],
         d['open_ports'], d['services'], d['version_map'], d['banner_map'],
         d['device_type'], d['display_name'])
        for ip, d in sorted(devices.items(), key=lambda item: tuple(map(int, item[0].split('.'))))
    ]


def _parse_device_record(device):
    (ip, hostname, os_type, is_mobile, mac, mac_vendor_, open_ports, services,
     version_map, banner_map, device_type, display_name) = device
    if not display_name:
        display_name = format_device_display_name(hostname, device_type, ip)
    return {
        'ip': ip, 'hostname': hostname, 'os': os_type, 'is_mobile': is_mobile,
        'mac': mac, 'mac_vendor': mac_vendor_, 'open_ports': open_ports or [],
        'services': services or [], 'version_map': version_map or {},
        'banner_map': banner_map or {}, 'device_type': device_type,
        'display_name': display_name,
    }


def build_dynamic_graph(devices):
    G = nx.DiGraph()
    node_type_map = {"Entry Node": "endpoint", "Server": "server",
                      "Database": "database", "Workstation": "endpoint"}

    parsed = [_parse_device_record(d) for d in devices]
    node_names = []

    for rec in parsed:
        role = assign_role_from_services(rec['services'], rec['os'], rec['device_type'])
        security = assess_device_security(
            rec['services'], rec['os'], rec['device_type'], rec['open_ports'], role,
            version_map=rec['version_map'], ip=rec['ip'],
        )
        ntype = node_type_map.get(role, "endpoint")
        node_name = f"{role}\n{rec['display_name']}"
        node_names.append(node_name)
        G.add_node(
            node_name,
            ip=rec['ip'], hostname=rec['hostname'], os=rec['os'],
            is_mobile=rec['is_mobile'], mac=rec['mac'], mac_vendor=rec['mac_vendor'],
            open_ports=rec['open_ports'], services=rec['services'],
            version_map=rec['version_map'], banner_map=rec['banner_map'],
            device_type=rec['device_type'], display_name=rec['display_name'],
            role=role, criticality=security['criticality'],
            vulnerability=security['vulnerability'], exposure_level=security['exposure_level'],
            risk_profile=security['risk_profile'], weaknesses=security['weaknesses'],
            access_vectors=security['access_vectors'], fixes=security['fixes'],
            cve_findings=security['cve_findings'], cve_source=security['cve_source'],
            node_type=ntype, compromised=False, priv_escalated=False,
        )

    for src in node_names:
        for dst in node_names:
            if src == dst:
                continue
            for edge_info in get_lateral_edges_for_target(G.nodes[dst]['open_ports']):
                G.add_edge(src, dst, connection=edge_info['connection'],
                           access_vector=edge_info['vector'], access_port=edge_info['port'],
                           mitre_code=edge_info['mitre_code'], mitre_desc=edge_info['mitre_desc'],
                           success_prob=edge_info['success_prob'])
    return G


def build_network():
    """Simulated lab topology (offline demo mode) — unchanged structure, now
    routed through the same real-CVE-aware assessment function with no
    version data, so it falls back cleanly to baseline risk."""
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
    for name, ip, role, ntype, open_ports, services in lab_hosts:
        os_type = 'linux' if ntype in ('server', 'database') else 'windows' if ntype == 'endpoint' else 'unknown'
        device_type = 'Server' if ntype == 'server' else 'Database Server' if ntype == 'database' else 'Computer'
        sim_role = 'Database' if ntype == 'database' else 'Server' if ntype == 'server' else 'Workstation'
        if name == 'Firewall':
            sim_role = 'Entry Node'
        security = assess_device_security(services, os_type, device_type, open_ports, sim_role, ip=ip)
        G.add_node(
            name, ip=ip, role=role, display_name=name, hostname=name, os=os_type,
            open_ports=open_ports, services=services, version_map={}, banner_map={},
            device_type=device_type, criticality=security['criticality'],
            vulnerability=security['vulnerability'], exposure_level=security['exposure_level'],
            risk_profile=security['risk_profile'], weaknesses=security['weaknesses'],
            access_vectors=security['access_vectors'], fixes=security['fixes'],
            cve_findings=security['cve_findings'], cve_source=security['cve_source'],
            node_type=ntype, compromised=False, priv_escalated=False,
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
                       success_prob=edge_info['success_prob'])
    return G


# ─────────────────────────────────────────────────────────────────
# MODULE 2: ATTACK SIMULATION ENGINE (probabilistic — no real exploitation)
# ─────────────────────────────────────────────────────────────────

def simulate_attack(G, entry_node, seed=42):
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
    max_hops = max((len(p) - 1 for p in attack_paths), default=0)

    stats = {
        "systems_controlled": len(real_compromised), "total_systems": len(real_nodes),
        "max_lateral_hops": max_hops, "privilege_escalations": len(priv_escalated),
        "attack_paths": attack_paths[:10], "reachable_from_entry": len(real_compromised),
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
        "attack_paths": stats.get("attack_paths", []),
    }
    return round(risk_score, 1), blast_details


# ─────────────────────────────────────────────────────────────────
# MODULE 4: DEFENSE OPTIMIZATION ENGINE
# ─────────────────────────────────────────────────────────────────

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
                "description": fix,
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
            })

    ids_cost = 30
    ids_reduction = round(risk_score * 0.12, 1)
    actions.append({
        "action": "Deploy Network IDS / SIEM", "node": "ALL", "type": "ids",
        "cost": ids_cost, "risk_reduction": ids_reduction,
        "efficiency": round(ids_reduction / ids_cost, 3),
        "description": "Detect lateral movement (Snort/Suricata/Wazuh) across the LAN",
    })

    segment_cost = 25
    segment_reduction = round(risk_score * 0.15, 1)
    actions.append({
        "action": "Network Segmentation (VLANs)", "node": "ALL", "type": "isolate",
        "cost": segment_cost, "risk_reduction": segment_reduction,
        "efficiency": round(segment_reduction / segment_cost, 3),
        "description": "Split workstations, servers, and databases into separate VLANs with ACLs",
    })

    actions.sort(key=lambda x: x["efficiency"], reverse=True)
    return actions


def greedy_defense_selection(actions, budget):
    selected, remaining_budget, total_reduction = [], budget, 0.0
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
        else:
            color = {"background": "#002d4a", "border": "#00d4ff", "highlight": {"background": "#003d60"}}
            size = 22

        cves = data.get('cve_findings', [])
        cve_html = ''.join(f"CVE: {c['cve_id']} (CVSS {c['cvss']})<br>" for c in cves[:2])
        tooltip = (
            f"<div style='font-family:Share Tech Mono;font-size:11px;color:#e0f4ff;background:#0d1f2d;padding:8px;border:1px solid #1a3a5c'>"
            f"<b style='color:#00d4ff'>{node}</b><br>IP: {data['ip']}<br>Role: {data['role']}<br>"
            f"Criticality: {'★' * data['criticality']}<br>Risk score: {int(data['vulnerability']*100)}/100<br>"
            f"{cve_html}"
            f"Status: {'🔴 COMPROMISED' if is_compromised else '🟡 HONEYPOT' if is_honeypot else '🟢 SECURE'}</div>"
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
        net.add_edge(src, dst, title=data.get("connection", ""), color=edge_color, width=width)

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
# MODULE 5B: ATTACK LOG GENERATOR
# ─────────────────────────────────────────────────────────────────

def generate_attack_log(timeline, honeypot_triggered):
    log = []
    mitre_log = {
        "T1190": "exploit_public_app", "T1078": "valid_account_brute",
        "T1021": "lateral_move", "T1005": "data_staged_exfil",
        "T1003": "credential_dump_lsass", "T1068": "priv_esc",
    }
    for i, entry in enumerate(timeline[:12]):
        node = entry["node"]
        action = mitre_log.get(entry.get("mitre_code", ""), "scan_probe")
        ip = "10.0.0." + str(random.randint(50, 254))
        status = "SUCCESS" if entry["success"] else "BLOCKED"
        severity = "critical" if entry["success"] else "ok"
        log.append({
            "time": f"09:{42+i:02d}:{random.randint(10,59):02d}", "src_ip": ip,
            "dst": node, "action": action, "status": status, "severity": severity,
        })
    if honeypot_triggered:
        log.append({"time": "09:50:01", "src_ip": "10.0.0.???", "dst": "Honeypot",
                     "action": "HONEYPOT_TRIGGER", "status": "⚠ TRAP SPRUNG", "severity": "critical"})
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

    risk_word = "CRITICAL" if risk_score > 70 else "ELEVATED" if risk_score > 40 else "LOW"

    lines = []
    lines.append(
        f"Starting from <b>{(entry_node or 'the chosen entry point').split(chr(10))[-1]}</b>, "
        f"this simulation estimates an attacker could reach "
        f"<b>{len(real_compromised)} of {blast_details.get('total_real_nodes', len(G.nodes))}</b> "
        f"systems on your network, including <b>{len(crown_jewels)}</b> high-value system(s) "
        f"such as servers or databases."
    )
    if top_cve:
        lines.append(
            f"The single most dangerous issue found was <b>{top_cve['cve_id']}</b> "
            f"(severity {top_cve['cvss']}/10) on the <b>{top_cve['service']}</b> service "
            f"(port {top_cve['port']}). Fixing this first gives the largest risk reduction "
            f"for the least effort."
        )
    lines.append(
        f"Overall business risk is rated <b>{risk_word}</b> ({risk_score}/100). "
        f"{'This needs attention this week.' if risk_word=='CRITICAL' else 'This should be scheduled into your next IT maintenance window.' if risk_word=='ELEVATED' else 'No urgent action required, but keep monitoring.'}"
    )
    return "<br><br>".join(lines)


def get_asset_metrics(G):
    """Return presentation metrics without mutating the discovery graph."""
    assets = list(G.nodes(data=True))
    risks = [float(data.get("vulnerability", 0)) * 100 for _, data in assets]
    services = sum(len(data.get("services", [])) for _, data in assets)
    servers = sum(data.get("node_type") in {"server", "database"} for _, data in assets)
    critical = sum(any(c.get("cvss", 0) >= 9 for c in data.get("cve_findings", [])) for _, data in assets)
    high = sum(any(7 <= c.get("cvss", 0) < 9 for c in data.get("cve_findings", [])) for _, data in assets)
    return {
        "assets": len(assets), "servers": servers, "services": services,
        "average_risk": round(sum(risks) / len(risks), 1) if risks else 0.0,
        "critical": critical, "high": high,
    }


# ─────────────────────────────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ─────────────────────────────────────────────────────────────────

defaults = {
    "network_mode": "Real Network Scan", "simulation_done": False, "timeline": [],
    "compromised": set(), "risk_score": 0.0, "blast_details": {},
    "honeypot_triggered": False, "defense_actions": [], "selected_defenses": [],
    "attack_log": [], "attack_stats": {}, "current_anim_node": None,
    "last_scan_devices": None, "scan_started_at": None, "scan_completed_at": None,
    "scan_error": None,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

if "G" not in st.session_state:
    st.session_state.G = build_network() if st.session_state.network_mode == "Simulated Lab" else nx.DiGraph()


# ─────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:16px 0 8px 0'>
        <div style='font-family:Orbitron,monospace;font-size:1.1rem;color:#00d4ff;letter-spacing:3px'>🛡 ACDS v2.0</div>
        <div style='font-family:Share Tech Mono,monospace;font-size:0.6rem;color:#3d6a8a;letter-spacing:2px'>ADAPTIVE CYBER DEFENSE SYSTEM</div>
        <div style='font-family:Share Tech Mono,monospace;font-size:0.6rem;color:#3d6a8a;letter-spacing:2px'>REAL CVE-BASED RISK ENGINE</div>
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
        st.session_state.attack_log = []
        st.session_state.current_anim_node = None
        st.session_state.G = build_network() if network_mode == "Simulated Lab" else nx.DiGraph()
        st.rerun()

    if network_mode == "Real Network Scan":
        st.markdown("""
        <div style='background:rgba(255,140,0,0.08);border:1px solid #ff8c00;padding:10px 12px;
             font-family:Share Tech Mono;font-size:0.65rem;color:#ff8c00;line-height:1.8;margin:8px 0'>
        ⚠ REAL NETWORK MODE — passive only<br>
        <span style='color:#3d6a8a'>
        • Discovers LAN hosts via ping + ARP/MAC<br>
        • Scans open ports and grabs real service banners<br>
        • Looks up real CVEs (NVD) for the detected versions<br>
        • Simulates lateral movement using real CVE severity<br>
        • Generates specific, per-host remediation steps
        </span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("""
        <div style='background:rgba(255,51,85,0.08);border:1px solid #ff3355;padding:8px 10px;
             font-family:Share Tech Mono;font-size:0.62rem;color:#ff3355;margin:8px 0'>
        Only scan networks you own or are authorized to test.
        </div>
        """, unsafe_allow_html=True)

        lab_preset = st.selectbox(
            "Lab network preset",
            ["Custom / Auto", "VMware NAT (192.168.93.x)", "Home LAN (192.168.1.x)"],
            help="VMware NAT is skipped by auto-detect — use this preset for VM lab targets",
        )

        if lab_preset == "VMware NAT (192.168.93.x)":
            base_ip = "192.168.93."
            preset_limit = 200
            st.info("VMware NAT lab: target VM usually at **192.168.93.128**. Setup guide: `lab/VM_LAB_SETUP.md`")
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

        scan_limit = st.slider(
            "Scan Range (last octet up to...)", 10, 254, preset_limit, 10,
        )

        if st.button("📡  SCAN NETWORK", use_container_width=True):
            progress_bar = st.progress(0, text="Starting scan...")

            def _progress(done, total):
                if total > 0:
                    progress_bar.progress(min(done / total, 1.0), text=f"Profiling host {done}/{total}...")

            st.session_state.scan_started_at = datetime.now(timezone.utc)
            st.session_state.scan_error = None
            try:
                with st.spinner("Pinging subnet and discovering hosts..."):
                    devices = scan_network(base_ip=base_ip, limit=scan_limit, progress_cb=_progress)
            except Exception as exc:
                devices = []
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
                st.session_state.attack_log = []
                st.session_state.current_anim_node = None
                st.session_state.G = build_dynamic_graph(devices)
                st.session_state.last_scan_devices = devices
                st.success(f"Found {len(devices)} device(s). Graph updated with real banners + CVE lookups.")
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

    show_honeypot = st.checkbox("Show Honeypot Node", value=True)
    animation_speed = st.slider("Animation Speed (sec/step)", 0.3, 2.0, 0.6, 0.1)

    st.markdown('<div class="section-header">💰 DEFENSE BUDGET</div>', unsafe_allow_html=True)
    all_actions_for_budget = get_defense_actions(
        st.session_state.G, set(st.session_state.G.nodes) - {"Honeypot"}, 50
    )
    max_budget = sum(a["cost"] for a in all_actions_for_budget) or 100
    budget = st.slider("Budget (units)", 0, max_budget, max_budget // 3)

    st.markdown('<div class="section-header">📡 NETWORK STATUS</div>', unsafe_allow_html=True)
    for node, data in st.session_state.G.nodes(data=True):
        status_class = "dot-compromised" if data["compromised"] else \
                       "dot-honeypot" if data.get("node_type") == "honeypot" else "dot-safe"
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
    <div class="cyber-subtitle">// REAL CVE DISCOVERY • ATTACK PATH ANALYSIS • DYNAMIC REMEDIATION // SME CYBERSECURITY //</div>
</div>
""", unsafe_allow_html=True)

if st.session_state.network_mode == "Real Network Scan":
    st.markdown("""
    <div style='background:rgba(255,140,0,0.06);border:1px solid #ff8c00;border-left:4px solid #ff8c00;
         padding:12px 18px;font-family:Share Tech Mono;font-size:0.72rem;color:#ff8c00;
         line-height:1.9;margin-bottom:16px'>
        <b>⚠ REAL NETWORK MODE ACTIVE — passive scan only</b><br>
        <span style='color:#7ab8d4'>
        • Device + service detection via ping/ARP/port scan + real banner grabbing<br>
        • Vulnerabilities matched against live NIST NVD CVE data for the exact version found<br>
        • Attack simulation shows lateral movement depth & systems controlled (probabilistic model)<br>
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
m1, m2, m3, m4, m5, m6 = st.columns(6)
with m1:
    st.metric("ASSETS", asset_metrics["assets"])
with m2:
    st.metric("SERVERS", asset_metrics["servers"])
with m3:
    st.metric("SERVICES", asset_metrics["services"])
with m4:
    st.metric("AVG. RISK", f"{asset_metrics['average_risk']}%")
with m5:
    st.metric("CRITICAL CVEs", asset_metrics["critical"])
with m6:
    scan_time = st.session_state.scan_completed_at
    st.metric("LAST SCAN", scan_time.strftime("%H:%M UTC") if scan_time else "Not run")

st.markdown('<hr style="border-color:#1a3a5c;margin:8px 0 20px 0">', unsafe_allow_html=True)

col_graph, col_details = st.columns([3, 2], gap="medium")

with col_graph:
    st.markdown('<div class="section-header">🗺 NETWORK TOPOLOGY MAP</div>', unsafe_allow_html=True)
    graph_placeholder = st.empty()
    html_graph = render_graph(st.session_state.G, compromised_set=st.session_state.compromised,
                               current_node=st.session_state.current_anim_node, show_honeypot=show_honeypot)
    with graph_placeholder:
        st.components.v1.html(html_graph, height=500, scrolling=False)

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

    st.markdown("<br>", unsafe_allow_html=True)
    run_col, reset_col = st.columns([2, 1])
    with run_col:
        run_btn = st.button("▶  RUN ATTACK SIMULATION", use_container_width=True)
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

    def render_node_panel(active_node=None, selected_node=None):
        html = ""
        for node, data in st.session_state.G.nodes(data=True):
            if selected_node and node != selected_node:
                continue
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
            vendor = data.get('mac_vendor')
            device_icon = {
                'Mobile Phone': '📱', 'Tablet': '📱', 'Router/Gateway': '🌐',
                'Server': '🖥️', 'Database Server': '🗄️', 'Computer': '💻',
                'Mac': '🍎', 'Network Device': '🔗',
            }.get(device_type, '📱' if is_mobile else '')
            vendor_suffix = f" ({vendor})" if vendor else ""
            device_html = (
                f"<div style='display:flex;align-items:center;margin:4px 0'>"
                f"<span style='color:#3d6a8a;width:70px'>Device:</span>"
                f"<span style='color:#e0f4ff'>{device_icon} {device_type or ('Mobile' if is_mobile else 'Unknown')}{vendor_suffix}</span>"
                f"</div>"
            ) if device_type or is_mobile else ""

            version_map = data.get('version_map', {})
            services = data.get('services', [])
            if version_map:
                svc_strs = [f"{s} ({version_map[s]})" if version_map.get(s) else s for s in services[:4]]
            else:
                svc_strs = services[:4]
            services_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Services:</span><span style='color:#e0f4ff'>{', '.join(svc_strs)}{'...' if len(services) > 4 else ''}</span></div>" if services else ""
            open_ports = data.get('open_ports', [])
            ports_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Ports:</span><span style='color:#e0f4ff'>{', '.join(str(p) for p in open_ports) or 'None detected'}</span></div>"
            risk_profile = data.get('risk_profile', {})
            risk_basis = html_lib.escape(risk_profile.get('basis', 'legacy assessment'))
            risk_score = risk_profile.get('score', int(data.get('vulnerability', 0) * 100))
            risk_severity = html_lib.escape(risk_profile.get('severity', 'Unknown'))
            risk_html = f"<div style='margin:6px 0;padding:6px;background:rgba(0,212,255,0.05);border-left:2px solid #00d4ff'><div style='color:#00d4ff;font-size:0.65rem'>RISK: {risk_score}/100 — {risk_severity}</div><div style='color:#7ab8d4;font-size:0.62rem'>{risk_basis}</div></div>"

            cve_findings = data.get('cve_findings', [])
            cve_html = ""
            if cve_findings:
                source_label = {"nvd_live": "NVD live", "offline_table": "offline reference"}.get(cve_findings[0].get('source'), '')
                cve_html = (
                    f"<div style='margin:6px 0;padding:6px;background:rgba(255,51,85,0.08);border-left:2px solid #ff3355'>"
                    f"<div style='color:#3d6a8a;font-size:0.62rem;margin-bottom:3px'>REAL CVEs FOUND ({source_label})</div>"
                    + "".join(
                        f"<div style='color:#ff3355;font-size:0.65rem'>• {c['cve_id']} (CVSS {c['cvss']}) — {c['summary'][:70]}{'...' if len(c['summary'])>70 else ''}</div>"
                        for c in cve_findings[:3]
                    ) + "</div>"
                )
            else:
                cve_html = "<div style='margin:6px 0;padding:6px;background:rgba(0,255,136,0.04);border-left:2px solid #00ff88;color:#7ab8d4;font-size:0.65rem'>No confirmed version-specific CVEs. Open services are shown as exposure, not proof of a vulnerability.</div>"

            weaknesses = data.get('weaknesses', [])
            weak_html = (
                f"<div style='margin:6px 0;padding:6px;background:rgba(255,140,0,0.06);border-left:2px solid #ff8c00'>"
                f"<div style='color:#3d6a8a;font-size:0.62rem;margin-bottom:3px'>OTHER EXPOSURE</div>"
                + "".join(f"<div style='color:#ff8c00;font-size:0.65rem'>• {w[:70]}{'...' if len(w)>70 else ''}</div>" for w in weaknesses[:2] if 'CVE' not in w)
                + "</div>"
            ) if any('CVE' not in w for w in weaknesses) else ""
            recommendations = data.get('fixes', [])
            recommendation_html = "".join(
                f"<div style='color:#7ab8d4;font-size:0.64rem'>• {html_lib.escape(fix)}</div>" for fix in recommendations[:2]
            )
            if recommendation_html:
                recommendation_html = f"<div style='margin:6px 0;padding:6px;background:rgba(0,255,136,0.04);border-left:2px solid #00ff88'><div style='color:#3d6a8a;font-size:0.62rem;margin-bottom:3px'>RECOMMENDED ACTIONS</div>{recommendation_html}</div>"

            html += (
                f"<div class='node-card {card_class}'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>"
                f"<span style='color:{node_color};font-family:Orbitron,monospace;font-size:0.8rem;font-weight:700'>{node}</span>"
                f"<span style='font-size:0.65rem;opacity:0.8'>{status_icon}</span></div>"
                f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>IP:</span><span style='color:#e0f4ff'>{data['ip']}</span></div>"
                f"{hostname_html}{os_html}{device_html}{ports_html}{services_html}{risk_html}{cve_html}{weak_html}{recommendation_html}"
                f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Role:</span><span style='color:#e0f4ff'>{data['role']}</span></div>"
                f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Criticality:</span><span style='color:#ffd700'>{crit_stars}</span></div>"
                f"<div style='margin:8px 0'><div style='color:#3d6a8a;margin-bottom:4px'>Risk score:</div>"
                f"<div class='risk-bar-container'><div class='risk-bar' style='width:{vuln_pct}%;background:{vuln_bar_color}'></div></div>"
                f"<span style='color:{vuln_bar_color}'>{vuln_pct}%</span></div></div>"
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
        st.session_state.G, entry_node, seed=random.randint(1, 9999)
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

            updated_html = render_graph(st.session_state.G, compromised_set=animated_compromised,
                                         current_node=node, show_honeypot=show_honeypot)
            with graph_placeholder:
                st.components.v1.html(updated_html, height=500, scrolling=False)
            node_panel.markdown(f"<div style='padding: 8px;'>{render_node_panel(active_node=node, selected_node=selected_asset)}</div>", unsafe_allow_html=True)
            time.sleep(animation_speed)

    status_text.markdown(
        '<div style="font-family:Share Tech Mono;font-size:0.75rem;color:#ffd700;'
        'background:#1a1000;border:1px solid #ffd700;padding:8px 14px;margin:4px 0">'
        '[ SIMULATION COMPLETE ] All attack vectors evaluated.</div>',
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

    st.session_state.defense_actions = get_defense_actions(st.session_state.G, compromised, risk_score)
    selected, total_reduction, remaining = greedy_defense_selection(st.session_state.defense_actions, budget)
    st.session_state.selected_defenses = selected
    st.session_state.attack_log = generate_attack_log(timeline, honeypot_triggered)

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
    st.markdown('<div class="section-header">📝 EXECUTIVE SUMMARY (PLAIN ENGLISH)</div>', unsafe_allow_html=True)
    summary_html = build_executive_summary(
        st.session_state.G, st.session_state.compromised, st.session_state.risk_score,
        st.session_state.blast_details, entry_node,
    )
    st.markdown(f"<div class='exec-summary'>{summary_html}</div>", unsafe_allow_html=True)

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)
    col_timeline, col_risk = st.columns([1, 1], gap="medium")

    with col_timeline:
        st.markdown('<div class="section-header">⏱ ATTACK TIMELINE</div>', unsafe_allow_html=True)
        for t, entries in sorted({e["timestep"]: None for e in st.session_state.timeline}.items()):
            pass
        ts_groups = {}
        for entry in st.session_state.timeline:
            ts_groups.setdefault(entry["timestep"], []).append(entry)
        for t, entries in sorted(ts_groups.items()):
            for entry in entries:
                is_success = entry["success"]
                bg_color = "rgba(255,51,85,0.1)" if is_success else "rgba(0,255,136,0.05)"
                border_color = "#ff3355" if is_success else "#00ff88"
                status_text_val = "✓ COMPROMISED" if is_success else "✗ BLOCKED"
                status_color = "#ff3355" if is_success else "#00ff88"
                privilege_html = "<div style='color:#ffd700;font-size:0.65rem'>⬆ Privilege Escalation</div>" if entry.get("priv_esc") else ""
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
                    <div style='color:#ff8c00;font-size:0.65rem'>Via: {entry.get("access_vector", "network")}</div>
                    {privilege_html}
                    <div style='color:#7ab8d4'>Risk: {vuln_percent}/100 | Criticality: {criticality_stars}</div>
                </div>
                """, unsafe_allow_html=True)

    with col_risk:
        st.markdown('<div class="section-header">📊 RISK ANALYSIS (BLAST RADIUS)</div>', unsafe_allow_html=True)
        rs = st.session_state.risk_score
        bd = st.session_state.blast_details
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
            <div>Spread (w1=0.3): <span style='color:#00d4ff;float:right'>{bd.get("spread",0)}% nodes compromised</span></div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("spread",0)}%;background:#00d4ff'></div></div>
            <div>Critical Impact (w2=0.5): <span style='color:#ff8c00;float:right'>{bd.get("critical_impact",0)}% criticality</span></div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("critical_impact",0)}%;background:#ff8c00'></div></div>
            <div>Attack Depth (w3=0.2): <span style='color:#ffd700;float:right'>{bd.get("depth",0)}% of network</span></div>
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
        st.markdown('<div class="section-header">🛡 DEFENSE OPTIMIZATION ENGINE</div>', unsafe_allow_html=True)
        st.markdown("""
        <div style='font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;
             background:#060d15;border:1px solid #1a3a5c;padding:10px;margin-bottom:12px;line-height:1.8'>
        // Greedy algorithm: rank by risk_reduction/cost ratio<br>
        // Select highest-value, CVE-specific actions within budget<br>
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
                <div style='color:#3d6a8a'>BUDGET USED</div><div style='color:#ffd700;font-size:1.2rem'>{spent} / {budget}</div>
            </div>
            <div style='flex:1;background:#0d1f2d;border:1px solid #00ff88;padding:12px;text-align:center;font-family:Share Tech Mono;font-size:0.72rem'>
                <div style='color:#3d6a8a'>RISK AFTER DEFENSE</div><div style='color:#00ff88;font-size:1.2rem'>{new_risk} / 100</div>
            </div>
            <div style='flex:1;background:#0d1f2d;border:1px solid #ff3355;padding:12px;text-align:center;font-family:Share Tech Mono;font-size:0.72rem'>
                <div style='color:#3d6a8a'>RISK REDUCTION</div><div style='color:#ff3355;font-size:1.2rem'>-{min(total_reduction_val, st.session_state.risk_score):.1f}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        selected_set = {a["action"] for a in selected_defenses}
        for action in all_actions[:10]:
            is_sel = action["action"] in selected_set
            card_class = "selected" if is_sel else "unselected"
            badge = "✓ SELECTED" if is_sel else "— SKIPPED"
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
                <span style='color:{badge_color};font-size:0.65rem;white-space:nowrap'>{badge}</span>
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
        mitre_html = "".join(f'<span class="mitre-tag">{code}</span>' for code in mitre_seen) + "<br><br>"
        for code, desc in mitre_seen.items():
            mitre_html += f'<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin:3px 0"><span style="color:#ff8c00">{code}</span> — {desc}</div>'
        st.markdown(f'<div style="background:#0d1f2d;border:1px solid #1a3a5c;padding:12px">{mitre_html}</div>', unsafe_allow_html=True)

        st.markdown('<br>', unsafe_allow_html=True)
        st.markdown('<div class="section-header">🦠 ALL REAL CVEs DISCOVERED ON NETWORK</div>', unsafe_allow_html=True)
        all_cves = []
        for node, data in st.session_state.G.nodes(data=True):
            for c in data.get('cve_findings', []):
                all_cves.append((node, data['ip'], c))
        all_cves.sort(key=lambda x: x[2]['cvss'], reverse=True)
        if all_cves:
            for node, ip, c in all_cves[:10]:
                st.markdown(f"""
                <div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;
                     padding:8px 10px;margin:4px 0;background:#0a1520;border-left:3px solid #ff3355">
                    <span class="cve-tag">{c['cve_id']}</span>
                    <span class="mitre-tag" style="border-color:#ff3355;color:#ff3355">CVSS {c['cvss']}</span>
                    <div style="margin-top:4px;color:#e0f4ff">{node.replace(chr(10),' / ')} ({ip}) — {c['service']} {c.get('version') or ''}</div>
                    <div style="margin-top:2px;color:#3d6a8a">{c['summary'][:120]}{'...' if len(c['summary'])>120 else ''}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No version-specific CVEs matched (services may be unversioned, patched, or NVD unreachable — '
                'baseline exposure risk was used instead).</div>',
                unsafe_allow_html=True,
            )

else:
    if st.session_state.network_mode == "Real Network Scan":
        ready_note = (
            "1. Click <span style='color:#ff8c00'>📡 SCAN NETWORK</span> in the sidebar to discover all LAN devices<br>"
            "2. The tool grabs real service banners and checks them against live NVD CVE data<br>"
            "3. Review each node's open ports, real CVEs, and specific recommended fixes<br>"
            "4. Select which system is <b>initially compromised</b> (attacker foothold)<br>"
            "5. Click <span style='color:#00d4ff'>▶ RUN ATTACK SIMULATION</span> to see lateral movement<br>"
            "6. Read the plain-English executive summary and prioritized fix list"
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
        <div style='color:#7ab8d4'>{ready_note}</div>
        <div style='color:#3d6a8a;margin-top:16px;font-size:0.65rem'>
            PASSIVE SCANNING ONLY — NO EXPLOITS PERFORMED<br>
            REAL CVE DATA FROM NIST NVD WHERE AVAILABLE<br>
            ALIGNED WITH MITRE ATT&CK FRAMEWORK
        </div>
    </div>
    """, unsafe_allow_html=True)
