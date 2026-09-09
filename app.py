# -*- coding: utf-8 -*-
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
import pandas as pd
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
import json
from collections import deque
from pyvis.network import Network
import tempfile
import os
import html as html_lib
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    # Sprint 3 — Phase 7 (operational reliability, applied early): a
    # missing optional dependency must never crash app startup — the PDF
    # download button is simply disabled with an explanatory message.
    REPORTLAB_AVAILABLE = False

# Persistence + adaptive modules (Priority 13/19/8-10 — see data/database.py,
# core/change_detector.py, core/honeypot_engine.py, core/vuln_dedup.py)
from data import database
from core import change_detector, honeypot_engine, vuln_dedup

# Sprint 1 — persistent asset inventory + background monitoring
# (core/database.py). Imported as monitor_db to avoid clashing with the
# existing `from data import database` above — the two modules serve
# different purposes and both stay active side by side.
from core import database as monitor_db
from core.database import generate_asset_id
from core.network_discovery import detect_network_environment, parse_target_ips

# Sprint 2 — Dynamic Risk Intelligence: graph-topology network exposure
# scoring (Phase 2/3) and the real-time alert engine (Phase 7). Both are
# pure logic modules — persistence goes through monitor_db (core/database.py)
# above, exactly like Sprint 1's change_detector/honeypot_engine.
from core import network_exposure, alert_engine

# Sprint 3 — Phase 7: shared rotating-file + console logger (core/acds_logging.py).
from core.acds_logging import get_logger
acds_log = get_logger("app")

# Level 2 — Real-Time Defensive Validation Engine (core/live_validation.py)
from core import live_validation
from core.live_validation import (
    validate_host_reachability,
    validate_tcp_port,
    validate_service_banner,
    validate_asset_state,
    validate_multiple_assets,
    diff_validation_against_discovery,
)
from core import device_fingerprinting

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
[data-testid="stSidebarCollapseButton"] span[data-testid="stIconMaterial"]::after,
[data-testid="collapsedControl"] span[data-testid="stIconMaterial"]::after {
    font-size: 1rem;
    content: '\\21C4';
}

/* Futuristic Cyberpunk Tab Navigation */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background-color: #060d15;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid #1a3a5c;
    margin-bottom: 20px;
}
.stTabs [data-baseweb="tab"] {
    font-family: var(--font-display), monospace;
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 1px;
    color: #7ab8d4;
    border-radius: 4px;
    padding: 10px 18px;
    transition: all 0.25s ease;
    border: 1px solid transparent;
    background: transparent;
}
.stTabs [data-baseweb="tab"]:hover {
    color: #00d4ff;
    background: rgba(0, 212, 255, 0.08);
    border-color: rgba(0, 212, 255, 0.3);
}
.stTabs [aria-selected="true"] {
    color: #00d4ff !important;
    background: rgba(0, 212, 255, 0.15) !important;
    border-color: #00d4ff !important;
    box-shadow: 0 0 15px rgba(0, 212, 255, 0.25);
}
.stTabs [data-baseweb="tab-border"] {
    display: none;
}
.stTabs [data-baseweb="tab-highlight"] {
    background-color: #00d4ff;
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

# Overall ACDS Risk aggregation weights (Priority 15 / Sprint 2 Phase 3)
# — ACDS design choice, must sum to 1.0. Sprint 2 extends the original
# two-component aggregation (Asset Risk 60% / Blast Radius 40%) with two
# additional documented components so the primary dashboard metric
# actually reflects Critical Asset Exposure and Network Exposure too,
# not just averaged per-host risk and simulated blast radius.
OVERALL_WEIGHT_ASSET_RISK = 0.40
OVERALL_WEIGHT_BLAST_RADIUS = 0.30
OVERALL_WEIGHT_CRITICAL_EXPOSURE = 0.15
OVERALL_WEIGHT_NETWORK_EXPOSURE = 0.15

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

# Sprint 3 — Phase 8: runtime-tunable operational settings. These start
# as the same hardcoded values Sprint 1/2 always used, and are
# overwritten from SQLite (core.database settings table) by
# apply_runtime_settings() once the session starts — see SESSION STATE
# INITIALIZATION below and the ⚙ SETTINGS panel for where they're edited.
SCAN_TIMEOUT_SECONDS = 0.6
BANNER_TIMEOUT_SECONDS = 1.2
NVD_CACHE_HOURS = 24
ALERT_SEVERITY_THRESHOLD = "LOW"
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def apply_runtime_settings(settings=None):
    """Sprint 3 — Phase 8: pull persisted settings from SQLite and apply
    them to the module-level knobs the rest of the app reads at call
    time (scan timeouts, NVD cache TTL, alert severity floor) and to
    SEVERITY_THRESHOLDS itself. Safe to call repeatedly — the Settings
    panel calls this immediately after saving so changes take effect
    without restarting the app."""
    global SEVERITY_THRESHOLDS, SCAN_TIMEOUT_SECONDS, BANNER_TIMEOUT_SECONDS
    global NVD_CACHE_HOURS, ALERT_SEVERITY_THRESHOLD
    if settings is None:
        settings = monitor_db.get_all_settings()
    SEVERITY_THRESHOLDS = (
        (settings.get("risk_threshold_critical", 85), 'CRITICAL'),
        (settings.get("risk_threshold_high", 65), 'HIGH'),
        (settings.get("risk_threshold_medium", 35), 'MEDIUM'),
        (0, 'LOW'),
    )
    SCAN_TIMEOUT_SECONDS = float(settings.get("scan_timeout_seconds", 0.6))
    BANNER_TIMEOUT_SECONDS = float(settings.get("banner_timeout_seconds", 1.2))
    NVD_CACHE_HOURS = int(settings.get("nvd_cache_hours", 24))
    ALERT_SEVERITY_THRESHOLD = settings.get("alert_severity_threshold", "LOW")

# Criticality normalization (Priority 10): 2=LOW .. 5=CRITICAL mapped to 0-100
CRITICALITY_LABELS = {2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}


def _safe_int(value):
    """SQLite TEXT-affinity columns can hand back numeric levels as
    strings (e.g. '5'); this normalizes for CRITICALITY_LABELS lookups
    without blowing up on None/'' from rows that predate this field."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
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
def lookup_cves_nvd(version_string, _retries=2):
    """
    Query the public NVD REST API for CVEs matching a free-text keyword
    (the parsed service/version string). In-process cached via lru_cache
    so we don't repeat the same network call twice in one run; the
    persisted, cross-restart cache lives in core.database.cve_cache and
    is checked by the caller (get_real_cves) before this function is
    ever invoked. Returns a list of dicts with id, cvss, severity,
    summary, fix_version, published, modified.

    Sprint 3 — Phase 7 (operational reliability): retries transient
    network failures (timeout/connection errors) up to `_retries` times
    with a short backoff before giving up — a single dropped packet to
    NVD shouldn't silently mean "no CVEs found" for the rest of the
    session (lru_cache would otherwise memoize that empty result
    forever). Non-transient failures (bad response, parse error) are
    NOT retried, since retrying those would just waste time.
    """
    if not REQUESTS_AVAILABLE or not version_string:
        return []
    last_transient_error = False
    for attempt in range(_retries + 1):
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
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            last_transient_error = True
            if attempt < _retries:
                time.sleep(0.6 * (attempt + 1))
                continue
            return []
        except (requests.RequestException, ValueError, KeyError):
            return []
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
    Try the persisted local cache first (Phase 7 — survives restarts and
    avoids re-hitting NVD's rate limits for a version string we've
    already resolved); then live NVD lookup; then the offline table;
    then nothing (caller uses the generic baseline risk).
    Returns (cves, source) where source in {'nvd_live','offline_table','none'}.
    """
    if not version_string:
        return [], "none"

    cached = monitor_db.get_cached_cve_lookup(version_string, max_age_hours=NVD_CACHE_HOURS)
    if cached is not None:
        return cached

    cves = lookup_cves_nvd(version_string)
    if cves:
        monitor_db.cache_cve_lookup(version_string, cves, "nvd_live")
        return cves, "nvd_live"
    cves = lookup_cves_offline(version_string)
    if cves:
        # Offline-table hits are cheap/local already, but caching them too
        # means a later NVD outage doesn't downgrade a version we already
        # have a confident offline match for.
        monitor_db.cache_cve_lookup(version_string, cves, "offline_table")
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
    """Dynamically detect the local machine's base IP prefix for scanning."""
    env = detect_network_environment()
    return env.get('base_ip_prefix') or "192.168.1."


def get_local_system_context():
    """Identify the scanning machine's own IP, hostname, OS and network environment dynamically."""
    env = detect_network_environment()
    return {
        'os': env.get('os', 'unknown'),
        'ip': env.get('controller_ip'),
        'hostname': env.get('controller_hostname'),
        'system': env.get('system', platform.system()),
        'adapter_name': env.get('adapter_name'),
        'subnet_cidr': env.get('subnet_cidr'),
        'gateway_ip': env.get('gateway_ip'),
        'netmask': env.get('netmask')
    }


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
                   banner_map=None, local_system_context=None, protocol_hints=None):
    """Evidence-based OS inference (Priority 2).

    TTL is only ever ONE of several supporting signals — it is never
    treated as decisive on its own. macOS and Linux both commonly reply
    with TTL 64, so TTL alone cannot separate them. Signals include:
    TTL, MAC vendor/LAA, hostname, protocol discovery (mDNS, NetBIOS, SSDP),
    exposed services, service banners, and local system identity.

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

    # 1) Local machine identity
    if local_system_context and local_system_context.get('ip') and ip == local_system_context['ip']:
        local_os = local_system_context.get('os')
        if local_os in scores:
            add(local_os, 0.90, "This IP matches the scanning machine's own local IP")

    # 2) Real-Time Protocol Discovery Probes (NetBIOS, mDNS, SSDP)
    if protocol_hints:
        if protocol_hints.get('netbios', {}).get('success'):
            add('windows', 0.55, "NetBIOS Name Service query confirmed Windows host stack")
        if protocol_hints.get('mdns', {}).get('is_apple'):
            add('macos', 0.55, "mDNS service discovery confirmed Apple device signature")
        if protocol_hints.get('mdns', {}).get('is_android_cast'):
            add('linux', 0.45, "mDNS service discovery confirmed Google Cast / Android stack")
        if protocol_hints.get('ssdp', {}).get('device_type') == 'Windows Host':
            add('windows', 0.45, "UPnP/SSDP device announcement indicated Windows")
        elif protocol_hints.get('ssdp', {}).get('device_type') in ('Android Device', 'Linux Host'):
            add('linux', 0.45, "UPnP/SSDP device announcement indicated Android/Linux")
        elif protocol_hints.get('ssdp', {}).get('device_type') == 'Apple Device':
            add('macos', 0.45, "UPnP/SSDP device announcement indicated Apple/Darwin")

    # 3) MAC vendor (OUI) — extended vendor resolution
    mac_vendor_resolved = mac_vendor_
    if not mac_vendor_resolved and mac:
        mac_vendor_resolved = device_fingerprinting.resolve_mac_vendor_extended(mac).get('vendor')

    if mac_vendor_resolved == 'Apple' or is_apple_vendor(mac):
        add('macos', 0.30, "Apple MAC vendor (also used by iPhone/iPad — cross-checked against hostname/services)")

    # 4) Hostname patterns
    if any(h in hl for h in _MACOS_HOSTNAME_HINTS):
        add('macos', 0.35, "Hostname resembles a macOS device")
    if any(h in hl for h in _LINUX_HOSTNAME_HINTS):
        add('linux', 0.30, "Hostname resembles a Linux device/distribution")
    if any(h in hl for h in _WINDOWS_HOSTNAME_HINTS):
        add('windows', 0.25, "Hostname resembles a Windows device")

    # 5) Service exposure fingerprints
    if any(s in services for s in ('SMB', 'RDP')):
        add('windows', 0.30, "SMB/RDP exposed — Windows-specific services")
    if 'NetBIOS' in services:
        add('windows', 0.10, "NetBIOS exposed — common on Windows")

    # 6) Service banner fingerprints
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

    # 7) TTL — SUPPORTING EVIDENCE ONLY.
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


def is_mobile_device(hostname, ip, mac=None, protocol_hints=None):
    """
    Real mobile detection: combine real-time protocol probing (mDNS, SSDP),
    MAC-vendor lookup, LAA privacy MAC recognition, and hostname pattern matching.
    """
    if is_tablet_device(hostname):
        return True

    if protocol_hints:
        if protocol_hints.get("is_mobile") or protocol_hints.get("mdns", {}).get("is_apple") or protocol_hints.get("mdns", {}).get("is_android_cast"):
            return True

    vendor = mac_vendor(mac)
    if not vendor and mac:
        ext = device_fingerprinting.resolve_mac_vendor_extended(mac)
        vendor = ext.get("vendor")
        if ext.get("is_randomized"):
            # Privacy MAC typical of smartphones on Wi-Fi
            return True

    if vendor in PHONE_VENDORS or (mac and device_fingerprinting.resolve_mac_vendor_extended(mac).get("vendor") in PHONE_VENDORS):
        if vendor != 'Apple':
            return True
        if hostname and any(w in hostname.lower() for w in ['macbook', 'imac', 'mac-mini', 'mac-pro']):
            return False
        if hostname and ('iphone' in hostname.lower() or 'ipad' in hostname.lower()):
            return True
        if not hostname:
            return True

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


def classify_device(hostname, os_type, os_confidence, is_mobile, services, open_ports, mac=None, protocol_hints=None):
    """Evidence-based device classification (Priority 3).

    Returns an "Inferred Device Type" rather than an absolute claim, with
    a confidence score and the concrete evidence used.
    """
    services = services or []
    open_ports = open_ports or []
    hl = (hostname or '').lower()
    evidence = []

    # Check for randomized privacy MAC
    is_rand_mac = device_fingerprinting.is_randomized_mac(mac) if mac else False
    if is_rand_mac:
        evidence.append("Randomized/Private MAC detected (IEEE LAA — typical of iOS/Android/Windows 11 Wi-Fi privacy)")

    if protocol_hints and protocol_hints.get("evidence"):
        evidence.extend(protocol_hints["evidence"])

    if is_tablet_device(hostname):
        return {'device_type': 'Tablet', 'confidence': 0.75,
                'evidence': ['Hostname matches known tablet naming pattern (e.g. iPad/tablet/Surface)']}

    if is_mobile:
        vendor_info = device_fingerprinting.resolve_mac_vendor_extended(mac)
        vendor = vendor_info.get("vendor")
        ev = ['Device identified as mobile via protocol/MAC/hostname patterns']
        if vendor and not is_rand_mac:
            ev.append(f"MAC vendor resolved to {vendor}")
        elif is_rand_mac:
            ev.append("Randomized Private MAC address active (typical of mobile Wi-Fi privacy)")
        if protocol_hints and protocol_hints.get("device_hint"):
            ev.append(protocol_hints["device_hint"])
        return {'device_type': 'Mobile Device', 'confidence': 0.75 if (vendor or is_rand_mac) else 0.55, 'evidence': ev + evidence}

    if any(h in hl for h in ['router', 'gateway', 'modem', 'ap-', 'wifi', 'fritz', 'tplink', 'netgear', 'asus']):
        return {'device_type': 'Network Device', 'confidence': 0.65,
                'evidence': ['Hostname matches known router/gateway/AP naming pattern'] + evidence}

    db_services = [s for s in services if s in ('MySQL', 'PostgreSQL', 'MongoDB', 'Redis')]
    if db_services:
        db_ports = [p for p in open_ports if PORT_SERVICE_MAP.get(p) in db_services]
        ev = [f"{s} detected" for s in db_services] + [f"Port {p} exposed" for p in db_ports]
        return {'device_type': 'Database Server', 'confidence': 0.90, 'evidence': ev + evidence}

    web_services = [s for s in services if s in ('HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt')]
    if web_services and os_type != 'macos':
        ev = [f"{s} service detected" for s in web_services]
        return {'device_type': 'Web Server', 'confidence': 0.65, 'evidence': ev + evidence}

    if os_type == 'macos':
        ev = ['OS inferred as macOS']
        if any(s in services for s in ('SSH', 'HTTP', 'HTTPS')):
            ev.append('Remote-access/web service open, but service alone does not override OS evidence')
        return {'device_type': 'Mac Computer', 'confidence': round(min(0.95, 0.5 + os_confidence * 0.4), 2),
                'evidence': ev + evidence}

    if os_type == 'windows':
        ev = ['OS inferred as Windows']
        if any(s in services for s in ('SMB', 'RDP')):
            ev.append('SMB/RDP service present (common on Windows workstations/servers)')
        role_guess = 'Windows Server' if any(s in services for s in ('HTTP', 'HTTPS', 'DNS')) else 'Windows Workstation'
        return {'device_type': role_guess, 'confidence': round(min(0.9, 0.45 + os_confidence * 0.4), 2),
                'evidence': ev + evidence}

    if os_type == 'linux':
        ev = ['OS inferred as Linux']
        role_guess = 'Linux Server' if any(s in services for s in ('SSH', 'HTTP', 'HTTPS', 'DNS', 'SMB')) else 'Linux Workstation'
        if role_guess == 'Linux Server':
            ev.append('Server-type service exposed (SSH/HTTP/DNS/SMB)')
        return {'device_type': role_guess, 'confidence': round(min(0.9, 0.45 + os_confidence * 0.4), 2),
                'evidence': ev + evidence}

    if services:
        return {'device_type': 'Unknown', 'confidence': 0.25,
                'evidence': [f"Services detected ({', '.join(services[:3])}) but OS evidence was insufficient to classify further"] + evidence}

    return {'device_type': 'Unknown', 'confidence': 0.10,
            'evidence': ['No OS or service evidence collected for this host'] + evidence}


def identify_device_type(hostname, os_type, is_mobile, services, mac=None, protocol_hints=None):
    """Backward-compatible thin wrapper returning just the label string
    (kept because several call sites only need the label). New code
    should call classify_device() directly for confidence + evidence."""
    return classify_device(hostname, os_type, 0.5, is_mobile, services, [], mac, protocol_hints=protocol_hints)['device_type']


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
        banner, raw_version = grab_banner(ip, port, timeout=BANNER_TIMEOUT_SECONDS)
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


def validate_scan_scope(base_ip, limit):
    """Sprint 3 — Phase 7: Scan Scope Validation. Rejects a malformed IPv4
    prefix or an out-of-range host count BEFORE any network operation
    starts, rather than silently generating garbage IP strings that
    would each individually fail deep inside scan_network(). Returns
    (True, None) if valid, else (False, human-readable reason)."""
    if not base_ip:
        return False, "Base IP prefix is empty."
    if not re.match(r'^(\d{1,3}\.){3}$', base_ip):
        return False, (f"'{base_ip}' doesn't look like a valid IPv4 prefix "
                        f"(expected e.g. '192.168.1.').")
    octets = base_ip.rstrip('.').split('.')
    if any(not (0 <= int(o) <= 255) for o in octets):
        return False, f"'{base_ip}' contains an octet outside 0–255."
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return False, "Scan range must be a number."
    if not (1 <= limit <= 254):
        return False, "Scan range must be between 1 and 254 hosts."
    return True, None


def scan_network(base_ip=None, limit=254, target_ips=None, progress_cb=None):
    """
    Full discovery pipeline: ping sweep -> ARP/MAC -> hostname -> port scan
    -> banner grab -> per-host record. Supports both dynamic subnet sweep and
    explicit target lists/ranges/CIDRs.
    """
    if target_ips:
        ips = list(target_ips)
        subnet_prefix = ips[0].rsplit('.', 1)[0] if ips else "192.168.1"
        target_desc = f"{len(ips)} target(s)"
    else:
        if base_ip is None:
            base_ip = get_local_ip()
        subnet_prefix = base_ip.rstrip('.')
        ips = [f"{base_ip}{i}" for i in range(1, limit + 1)]
        target_desc = f"{base_ip}0/{limit}"

    system = platform.system()
    timeline = []
    timeline.append({'timestamp': _now_stamp(), 'event': 'Ping sweep started', 'target': target_desc, 'status': 'Running'})

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
    
    if target_ips:
        candidate_ips = set(target_ips)
    else:
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
            open_ports = scan_ports(ip, SCAN_PORTS, timeout=SCAN_TIMEOUT_SECONDS) if ip in ping_results else []
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

        # Real-time protocol device fingerprinting (mDNS, NetBIOS, SSDP, LAA MAC)
        try:
            proto_fp = device_fingerprinting.fingerprint_asset_realtime(ip, mac=mac, current_hostname=hostname, open_ports=open_ports, services=services)
            if proto_fp.get("resolved_hostname") and (not hostname or hostname == "Unknown" or hostname == ip):
                hostname = proto_fp["resolved_hostname"]
                host_events.append({'timestamp': _now_stamp(), 'event': 'Protocol discovery hostname', 'target': hostname, 'status': 'Discovered'})
            if proto_fp.get("mac_vendor") and not vendor:
                vendor = proto_fp["mac_vendor"]
        except Exception:
            proto_fp = None

        # OS is inferred AFTER services/banners & protocol fingerprints are collected
        try:
            os_result = infer_os_type(ip, ttl, hostname, mac, vendor, services,
                                       banner_map=banner_map, local_system_context=local_ctx,
                                       protocol_hints=proto_fp)
        except Exception as exc:
            os_result = {'os': 'unknown', 'confidence': 0.0, 'evidence': [f'OS inference failed: {type(exc).__name__}']}
        host_events.append({'timestamp': _now_stamp(), 'event': 'OS inferred', 'target': f"{os_result['os']} ({int(os_result['confidence']*100)}%)", 'status': 'Completed'})

        is_mobile = is_mobile_device(hostname, ip, mac, protocol_hints=proto_fp)
        device_result = classify_device(hostname, os_result['os'], os_result['confidence'], is_mobile, services, open_ports, mac, protocol_hints=proto_fp)
        host_events.append({'timestamp': _now_stamp(), 'event': 'Asset classified', 'target': device_result['device_type'], 'status': 'Completed'})
        display_name = format_device_display_name(hostname, device_result['device_type'], ip)
        asset_id = generate_asset_id(mac, ip, hostname, vendor, os_result['os'])

        for svc in services:
            if version_map.get(svc):
                host_events.append({'timestamp': _now_stamp(), 'event': 'NVD lookup completed', 'target': f"{svc} {version_map.get(svc)}", 'status': 'Completed'})

        return {
            'asset_id': asset_id,
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
         d['banner_map'], d['device_type'], d['display_name'], d['device_confidence'], d['device_evidence'],
         d.get('asset_id', generate_asset_id(d['mac'], ip, d['hostname'], d['mac_vendor'], d['os'])))
        for ip, d in sorted(devices.items(), key=lambda item: tuple(map(int, item[0].split('.'))))
    ]
    return ordered, timeline


def profile_single_target(target_ip):
    """
    Fast discovery and profiling for an explicitly selected target IP.
    Reuses the real observation pipeline: ICMP ping, ARP/MAC lookup,
    hostname resolution, native socket port probing, banner grabbing,
    OS inference, and device classification.
    """
    system = platform.system()
    timeline = []
    timeline.append({'timestamp': _now_stamp(), 'event': 'Direct probe initiated', 'target': target_ip, 'status': 'Running'})

    # 1. ICMP Ping Probe
    _, is_alive, ttl = ping_ip(target_ip, system)
    timeline.append({'timestamp': _now_stamp(), 'event': 'ICMP Ping Probe', 'target': target_ip,
                     'status': f'Alive (TTL={ttl})' if is_alive else 'No Ping Response (proceeding to ARP/TCP probe)'})

    # 2. ARP / MAC Resolution
    subnet_prefix = target_ip.rsplit('.', 1)[0]
    arp_map = read_arp_map(subnet_prefix)
    mac = arp_map.get(target_ip)
    if not mac and system == "Windows":
        mac = lookup_mac_windows(target_ip)
    if mac:
        timeline.append({'timestamp': _now_stamp(), 'event': 'ARP/MAC resolved', 'target': f"{target_ip} ({mac})", 'status': 'Resolved'})

    hostname = resolve_hostname(target_ip)
    vendor = mac_vendor(mac)
    local_ctx = get_local_system_context()

    # 3. Safe TCP Port Probing
    try:
        open_ports = scan_ports(target_ip, SCAN_PORTS, timeout=SCAN_TIMEOUT_SECONDS)
    except Exception as exc:
        open_ports = []
        timeline.append({'timestamp': _now_stamp(), 'event': 'Port scan failed', 'target': target_ip, 'status': f'Unavailable ({type(exc).__name__})'})
    else:
        timeline.append({'timestamp': _now_stamp(), 'event': 'Ports probed',
                         'target': ', '.join(str(p) for p in open_ports) if open_ports else 'None open on tested list',
                         'status': 'Completed'})

    # 4. Service Identification & Banner Grabbing
    try:
        services, version_map, banner_map = detect_services_and_versions(target_ip, open_ports)
    except Exception as exc:
        services, version_map, banner_map = [], {}, {}
        timeline.append({'timestamp': _now_stamp(), 'event': 'Banner grab failed', 'target': target_ip, 'status': f'Unavailable ({type(exc).__name__})'})
    else:
        if services:
            timeline.append({'timestamp': _now_stamp(), 'event': 'Banners retrieved', 'target': ', '.join(services), 'status': 'Completed'})

    # Real-time protocol device fingerprinting (mDNS, NetBIOS, SSDP, LAA MAC)
    try:
        proto_fp = device_fingerprinting.fingerprint_asset_realtime(target_ip, mac=mac, current_hostname=hostname, open_ports=open_ports, services=services)
        if proto_fp.get("resolved_hostname") and (not hostname or hostname == "Unknown" or hostname == target_ip):
            hostname = proto_fp["resolved_hostname"]
            timeline.append({'timestamp': _now_stamp(), 'event': 'Protocol discovery hostname', 'target': hostname, 'status': 'Discovered'})
        if proto_fp.get("mac_vendor") and not vendor:
            vendor = proto_fp["mac_vendor"]
    except Exception:
        proto_fp = None

    # 5. Contextual OS Inference & Device Classification
    try:
        os_result = infer_os_type(target_ip, ttl, hostname, mac, vendor, services,
                                   banner_map=banner_map, local_system_context=local_ctx,
                                   protocol_hints=proto_fp)
    except Exception as exc:
        os_result = {'os': 'unknown', 'confidence': 0.0, 'evidence': [f'OS inference failed: {type(exc).__name__}']}
    timeline.append({'timestamp': _now_stamp(), 'event': 'OS inferred', 'target': f"{os_result['os']} ({int(os_result['confidence']*100)}%)", 'status': 'Completed'})

    is_mobile = is_mobile_device(hostname, target_ip, mac, protocol_hints=proto_fp)
    device_result = classify_device(hostname, os_result['os'], os_result['confidence'], is_mobile, services, open_ports, mac, protocol_hints=proto_fp)
    display_name = format_device_display_name(hostname, device_result['device_type'], target_ip)
    asset_id = generate_asset_id(mac, target_ip, hostname, vendor, os_result['os'])

    record = {
        'asset_id': asset_id,
        'ip': target_ip, 'hostname': hostname, 'os': os_result['os'],
        'os_confidence': os_result['confidence'], 'os_evidence': os_result['evidence'],
        'is_mobile': is_mobile, 'mac': mac, 'mac_vendor': vendor,
        'open_ports': open_ports, 'services': services,
        'version_map': version_map, 'banner_map': banner_map,
        'device_type': device_result['device_type'],
        'device_confidence': device_result['confidence'],
        'device_evidence': device_result['evidence'],
        'display_name': display_name, 'events': timeline,
        'ttl': ttl,
    }

    device_tuple = (
        target_ip, hostname, os_result['os'], os_result['confidence'], os_result['evidence'],
        is_mobile, mac, vendor, open_ports, services, version_map, banner_map,
        device_result['device_type'], display_name, device_result['confidence'], device_result['evidence'],
        asset_id
    )

    return record, device_tuple


def _parse_device_record(device):
    if isinstance(device, dict):
        rec = dict(device)
        if not rec.get('asset_id'):
            rec['asset_id'] = generate_asset_id(rec.get('mac'), rec.get('ip'), rec.get('hostname'), rec.get('mac_vendor'), rec.get('os'))
        if not rec.get('display_name'):
            rec['display_name'] = format_device_display_name(rec.get('hostname'), rec.get('device_type'), rec.get('ip'))
        return rec

    if len(device) >= 17:
        (ip, hostname, os_type, os_confidence, os_evidence, is_mobile, mac, mac_vendor_,
         open_ports, services, version_map, banner_map, device_type, display_name,
         device_confidence, device_evidence, asset_id) = device[:17]
    else:
        (ip, hostname, os_type, os_confidence, os_evidence, is_mobile, mac, mac_vendor_,
         open_ports, services, version_map, banner_map, device_type, display_name,
         device_confidence, device_evidence) = device[:16]
        asset_id = generate_asset_id(mac, ip, hostname, mac_vendor_, os_type)

    if not display_name:
        display_name = format_device_display_name(hostname, device_type, ip)
    return {
        'asset_id': asset_id,
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
            asset_id=rec.get('asset_id'),
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

    # Sprint 2 — Phase 2: now that the full exposure graph (nodes + lateral
    # edges) exists, recompute each asset's Network Exposure component from
    # real graph topology (reachable assets, degree centrality, sensitive
    # lateral services) instead of the placeholder "other asset count" used
    # while building nodes above, then reflow that into Asset Risk (Priority 18).
    network_exposure.apply_network_exposure_scores(G, SENSITIVE_PORTS, recompute_node_risk)
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

    # Sprint 2 — Phase 2: same graph-topology exposure recompute as the real
    # scan path, so the simulated lab demo also shows non-placeholder numbers.
    network_exposure.apply_network_exposure_scores(G, SENSITIVE_PORTS, recompute_node_risk)
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
# MODULE 2: DECISION-BASED ATTACK PROPAGATION SIMULATION ENGINE
# (probabilistic, empirical graph physics — no real exploitation)
# ─────────────────────────────────────────────────────────────────
# PRIORITY 26 BOUNDARY: everything below operates ONLY on the in-memory
# NetworkX graph built from passive scan data. It never sends network
# traffic, never authenticates anywhere, and never performs real
# exploitation, credential attacks, or data exfiltration.

def simulate_decision_based_propagation(G, entry_node, seed=42, ids_deployed=False, segmentation_applied=False, applied_rules=None, live_validation=None):
    """
    Dynamic Decision-Based Attack Propagation Simulator (ACDS Level 2).
    Combines:
      1. Real Discovery Observation (discovered topology & services)
      2. Real-Time Defensive Validation (live TCP port / host reachability)
      3. Decision-Based Attack Propagation (candidate-by-candidate evaluation)

    Evaluates whether an attack can propagate from a compromised source to neighboring targets based on:
      - Live Target Reachability (verified non-destructively)
      - Live Exposed Service / TCP Port Acceptance (verified non-destructively)
      - Valid Vulnerability (CVE) or Sensitive Access Condition (e.g. SMB, RDP, SSH, DB port) or Honeypot Trap
      - Defensive Controls (host containment/isolation, firewall ACLs, VLAN segmentation)
      - Modeled Propagation Probability

    Chaining: Newly compromised assets dynamically become subsequent attack sources.
    Every evaluated candidate target produces an explicit decision:
      - ✓ COMPROMISE POSSIBLE (Simulated)
      - ✗ COMPROMISE NOT POSSIBLE (Simulated)
      - 🛡 BLOCKED BY DEFENSE (Simulated)
      - ✗ NO VALID PATH (Simulated)
    along with exact explanations, MITRE ATT&CK techniques, probability calculations,
    and clear distinction between Observation, Validation, and Simulation.
    """
    random.seed(seed)
    timeline = []
    decision_log = []
    compromised = set()
    priv_escalated = set()
    attack_paths = []
    successful_paths = []
    blocked_failed_paths = []
    honeypot_triggered = False

    if entry_node not in G.nodes:
        return timeline, decision_log, compromised, set(G.nodes), successful_paths, blocked_failed_paths, {}

    entry_data = G.nodes[entry_node]
    compromised.add(entry_node)
    G.nodes[entry_node]["compromised"] = True

    entry_display = entry_data.get("display_name") or entry_node
    entry_asset_id = entry_data.get("asset_id") or entry_node
    entry_ip = entry_data.get("ip") or ""

    # Check if entry node was evaluated in live validation
    entry_val = None
    if live_validation and isinstance(live_validation, dict):
        entry_val = live_validation.get(entry_asset_id) or live_validation.get(entry_ip) or live_validation.get(entry_node)

    entry_live_txt = " (Live Validated: ONLINE)" if (entry_val and entry_val.get("reachable")) else ""

    timeline.append({
        "node": entry_node, "from_node": None, "timestep": 1,
        "mitre_code": "T1078", "mitre_desc": "Initial Access — simulated foothold on entry system",
        "access_vector": f"Simulated initial access on {entry_display}{entry_live_txt}",
        "success": True, "vuln": entry_data.get("vulnerability", 0.5),
        "criticality": entry_data.get("criticality", 1), "ntype": entry_data.get("node_type", "endpoint"),
        "priv_esc": False,
    })
    attack_paths.append([entry_node])

    # Initial Compromise Entry in Decision Log
    decision_log.append({
        "step": 1,
        "source": "EXTERNAL ATTACKER",
        "source_node": None,
        "source_id": "EXTERNAL",
        "target": entry_display,
        "target_node": entry_node,
        "target_id": entry_asset_id,
        "target_ip": entry_ip,
        "path": f"EXTERNAL → INITIAL FOOTHOLD → {entry_display}",
        "service": f"{', '.join(entry_data.get('services', [])) or 'Host Access'}",
        "vulnerability": f"{entry_data.get('cve_findings', [{}])[0].get('cve_id') if entry_data.get('cve_findings') else 'Assumed Foothold'}",
        "technique": "T1078 — Valid Accounts / Initial Access",
        "decision": "✓ COMPROMISE POSSIBLE",
        "probability": "100%",
        "prob_float": 1.0,
        "reason": f"✓ Modeled entry point foothold initialized on target asset{entry_live_txt}",
        "result_status": "SIMULATED COMPROMISED",
        "is_compromised": True,
        "live_validated": bool(entry_val),
        "live_host_reachable": entry_val.get("reachable") if entry_val else None,
        "live_port_state": "OPEN" if entry_val else None,
        "live_snapshot_used": not bool(entry_val),
    })

    # Active evaluation queue of newly compromised attack sources
    queue = deque([(entry_node, 1, [entry_node])])
    step_counter = 2

    # Global defense dampeners
    global_dampener = 1.0
    if ids_deployed:
        global_dampener *= 0.75   # faster detection/response cuts lateral success odds
    if segmentation_applied:
        global_dampener *= 0.55   # VLAN ACLs remove or heavily restrict lateral paths

    while queue:
        current_node, timestep, current_path = queue.popleft()
        if current_node not in compromised:
            continue

        src_data = G.nodes[current_node]
        src_display = src_data.get("display_name") or current_node
        src_asset_id = src_data.get("asset_id") or current_node
        src_ip = src_data.get("ip") or ""

        # Candidates: direct successors in graph or all other network assets
        candidate_targets = [n for n in G.nodes if n != current_node and n not in compromised]

        for target in candidate_targets:
            if target in compromised:
                continue

            dst_data = G.nodes[target]
            dst_display = dst_data.get("display_name") or target
            dst_asset_id = dst_data.get("asset_id") or target
            dst_ip = dst_data.get("ip") or ""
            dst_ntype = dst_data.get("node_type", "endpoint")
            is_honeypot = (dst_ntype == "honeypot")

            # ─────────────────────────────────────────────────────────────
            # 0. REAL-TIME DEFENSIVE VALIDATION (LEVEL 2 ENGINE)
            # ─────────────────────────────────────────────────────────────
            target_live_val = None
            if live_validation and isinstance(live_validation, dict):
                target_live_val = (
                    live_validation.get(dst_asset_id)
                    or live_validation.get(dst_ip)
                    or live_validation.get(target)
                )

            is_live_validated = target_live_val is not None
            live_host_reachable = target_live_val.get("reachable") if is_live_validated else None
            live_ports_map = (target_live_val.get("ports_validated") or target_live_val.get("ports") or {}) if (is_live_validated and target_live_val) else {}

            # If real-time validation explicitly found host to be OFFLINE/UNREACHABLE:
            if is_live_validated and live_host_reachable is False:
                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": f"{src_display} ⊘ {dst_display}",
                    "service": "Host Reachability",
                    "vulnerability": "N/A (Host Offline)",
                    "technique": "T1018 — Remote System Discovery [OFFLINE]",
                    "decision": "✗ NO VALID PATH",
                    "probability": "0%",
                    "prob_float": 0.0,
                    "reason": f"✗ Real-time validation confirms target host {dst_ip} is UNREACHABLE / OFFLINE (validation timestamp: {target_live_val.get('timestamp', 'recent')})",
                    "result_status": "UNCOMPROMISED",
                    "is_compromised": False,
                    "live_validated": True,
                    "live_host_reachable": False,
                    "live_port_state": "N/A",
                    "live_snapshot_used": False,
                })
                blocked_failed_paths.append({
                    "source": src_display, "target": dst_display, "decision": "✗ NO VALID PATH",
                    "reason": f"Host {dst_ip} is unreachable in real-time validation"
                })
                step_counter += 1
                continue

            # ─────────────────────────────────────────────────────────────
            # 1. EVALUATE TOPOLOGY REACHABILITY & PATH
            # ─────────────────────────────────────────────────────────────
            has_edge = G.has_edge(current_node, target)
            edge = G.edges[current_node, target] if has_edge else {}

            if not has_edge and not dst_data.get("open_ports"):
                val_note = " (live validated offline)" if (is_live_validated and not live_host_reachable) else " [Using discovery snapshot — live validation not performed]" if not is_live_validated else ""
                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": f"{src_display} ⊘ {dst_display}",
                    "service": "None",
                    "vulnerability": "None",
                    "technique": "N/A",
                    "decision": "✗ NO VALID PATH",
                    "probability": "0%",
                    "prob_float": 0.0,
                    "reason": f"No reachable network service or route identified on target asset{val_note}",
                    "result_status": "UNCOMPROMISED",
                    "is_compromised": False,
                    "live_validated": is_live_validated,
                    "live_host_reachable": live_host_reachable,
                    "live_port_state": "N/A",
                    "live_snapshot_used": not is_live_validated,
                })
                blocked_failed_paths.append({
                    "source": src_display, "target": dst_display, "decision": "✗ NO VALID PATH",
                    "reason": "No reachable network service or route identified"
                })
                step_counter += 1
                continue

            # ─────────────────────────────────────────────────────────────
            # 2. EVALUATE MODELED DEFENSES (ISOLATION & SEGMENTATION)
            # ─────────────────────────────────────────────────────────────
            if dst_data.get("isolated"):
                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": f"{src_display} ⊘ {dst_display}",
                    "service": f"{', '.join(dst_data.get('services', [])) or 'Isolated'}",
                    "vulnerability": "Shielded by Isolation",
                    "technique": "T1599 — Network Boundary Bridging [BLOCKED]",
                    "decision": "🛡 BLOCKED",
                    "probability": "0%",
                    "prob_float": 0.0,
                    "reason": "A modeled host isolation defense control prevents any inbound lateral propagation",
                    "result_status": "UNCOMPROMISED",
                    "is_compromised": False,
                    "live_validated": is_live_validated,
                    "live_host_reachable": live_host_reachable,
                    "live_port_state": "ISOLATED",
                    "live_snapshot_used": not is_live_validated,
                })
                blocked_failed_paths.append({
                    "source": src_display, "target": dst_display, "decision": "🛡 BLOCKED",
                    "reason": "Target isolated by host containment control"
                })
                timeline.append({
                    "node": target, "from_node": current_node, "timestep": timestep + 1,
                    "mitre_code": "T1599", "mitre_desc": "Network Boundary Bridging — blocked by host isolation",
                    "access_vector": "Blocked by applied isolation defense control",
                    "success": False, "vuln": dst_data.get("vulnerability", 0), "criticality": dst_data.get("criticality", 1),
                    "ntype": dst_ntype, "priv_esc": False,
                })
                step_counter += 1
                continue

            if segmentation_applied and (src_data.get("role") != dst_data.get("role") or dst_data.get("criticality", 1) >= 4):
                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": f"{src_display} ⊘ {dst_display}",
                    "service": f"{', '.join(dst_data.get('services', [])) or 'Segmented'}",
                    "vulnerability": "Segmented by Zone Policy",
                    "technique": "T1599 — Network Boundary Bridging [BLOCKED]",
                    "decision": "🛡 BLOCKED",
                    "probability": "0%",
                    "prob_float": 0.0,
                    "reason": "Applied dynamic segmentation blocks lateral movement across security zones",
                    "result_status": "UNCOMPROMISED",
                    "is_compromised": False,
                    "live_validated": is_live_validated,
                    "live_host_reachable": live_host_reachable,
                    "live_port_state": "SEGMENTED",
                    "live_snapshot_used": not is_live_validated,
                })
                blocked_failed_paths.append({
                    "source": src_display, "target": dst_display, "decision": "🛡 BLOCKED",
                    "reason": "Segmented by zone policy control"
                })
                timeline.append({
                    "node": target, "from_node": current_node, "timestep": timestep + 1,
                    "mitre_code": "T1599", "mitre_desc": "Network Boundary Bridging — blocked by VLAN segmentation",
                    "access_vector": "Blocked by applied segmentation defense control",
                    "success": False, "vuln": dst_data.get("vulnerability", 0), "criticality": dst_data.get("criticality", 1),
                    "ntype": dst_ntype, "priv_esc": False,
                })
                step_counter += 1
                continue

            # ─────────────────────────────────────────────────────────────
            # 3. SELECT ACCESS PORT & SERVICE (Observation vs Live Validation)
            # ─────────────────────────────────────────────────────────────
            edge_port = edge.get("port")
            edge_srv = edge.get("service", "TCP")
            open_ports = dst_data.get("open_ports", [])
            services = dst_data.get("services", [])

            if edge_port:
                access_port = edge_port
                access_service = edge_srv
            elif open_ports:
                access_port = open_ports[0]
                access_service = services[0] if services else f"Port-{access_port}"
            else:
                access_port = 80
                access_service = "HTTP"

            path_str = f"{src_display} → TCP/{access_port} ({access_service}) → {dst_display}"

            # ── Check Real-Time Live Port State ──
            live_port_entry = live_ports_map.get(access_port) or live_ports_map.get(str(access_port))
            live_port_state = None
            if live_port_entry:
                if isinstance(live_port_entry, dict):
                    raw_st = live_port_entry.get("state")
                    if raw_st is None and "open" in live_port_entry:
                        raw_st = "open" if live_port_entry["open"] else "closed"
                    live_port_state = str(raw_st).lower() if raw_st else None
                elif isinstance(live_port_entry, str):
                    live_port_state = live_port_entry.lower()

            # If live validation confirms port is CLOSED (e.g. defense applied / service stopped):
            if live_port_state == "closed":
                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": path_str,
                    "service": f"{access_service} (TCP {access_port})",
                    "vulnerability": "Attack Surface Removed (Port Closed)",
                    "technique": "T1046 — Network Service Discovery [CLOSED]",
                    "decision": "✗ COMPROMISE NOT POSSIBLE",
                    "probability": "0%",
                    "prob_float": 0.0,
                    "reason": f"✓ Host reachable (validated live) | ✗ Required port TCP/{access_port} ({access_service}) is CLOSED in real-time validation | ✗ Attack surface no longer exposed",
                    "result_status": "UNCOMPROMISED",
                    "is_compromised": False,
                    "live_validated": True,
                    "live_host_reachable": True,
                    "live_port_state": "CLOSED",
                    "live_snapshot_used": False,
                })
                blocked_failed_paths.append({
                    "source": src_display, "target": dst_display, "decision": "✗ COMPROMISE NOT POSSIBLE",
                    "reason": f"Required port TCP/{access_port} ({access_service}) verified CLOSED in real-time validation"
                })
                timeline.append({
                    "node": target, "from_node": current_node, "timestep": timestep + 1,
                    "mitre_code": "T1046", "mitre_desc": f"Service Scanning — port TCP/{access_port} closed (verified live)",
                    "access_vector": f"Real-time validation: TCP/{access_port} closed",
                    "success": False, "vuln": 0, "criticality": dst_data.get("criticality", 1),
                    "ntype": dst_ntype, "priv_esc": False,
                })
                step_counter += 1
                continue

            # ─────────────────────────────────────────────────────────────
            # 4. EVALUATE VULNERABILITY / ACCESS CONDITION
            # ─────────────────────────────────────────────────────────────
            cve_findings = dst_data.get("cve_findings", [])
            has_cve = bool(cve_findings)
            has_sensitive = access_port in SENSITIVE_PORTS
            vuln_score = dst_data.get("vulnerability", 0.3)

            condition_satisfied = False
            technique_code = "T1021"
            technique_desc = f"Remote Services ({access_service})"
            vuln_desc = "Service Exposure"

            if is_honeypot:
                condition_satisfied = True
                technique_code = "T1003"
                technique_desc = "OS Credential Dumping [DECOY TRAP]"
                vuln_desc = "Adaptive Honeypot Decoy Tripwire"
            elif has_cve:
                condition_satisfied = True
                top_cve = cve_findings[0]
                technique_code = edge.get("mitre_code", "T1210")
                technique_desc = f"Exploitation of Remote Services — {top_cve.get('cve_id')}"
                vuln_desc = f"{top_cve.get('cve_id')} (CVSS {top_cve.get('cvss')})"
            elif has_sensitive:
                condition_satisfied = True
                technique_code = edge.get("mitre_code", "T1021")
                technique_desc = edge.get("mitre_desc", f"Lateral Movement via {access_service}")
                vuln_desc = f"Sensitive Lateral Port (TCP {access_port} / {access_service})"
            elif vuln_score >= 0.25:
                condition_satisfied = True
                technique_code = "T1046"
                technique_desc = "Network Service Exploitation / Weak Config"
                vuln_desc = "Exposed Unauthenticated Listener"
            else:
                condition_satisfied = False

            val_label = (
                "✓ Real-time validated: Host reachable & port OPEN"
                if (is_live_validated and live_port_state == "open")
                else "[Using discovery snapshot — live validation not performed]"
            )

            if not condition_satisfied:
                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": path_str,
                    "service": f"{access_service} (TCP {access_port})",
                    "vulnerability": "Hardened / No Exploit Vector",
                    "technique": "N/A",
                    "decision": "✗ COMPROMISE NOT POSSIBLE",
                    "probability": "0%",
                    "prob_float": 0.0,
                    "reason": f"{val_label} | ✗ No matching vulnerability or sensitive access condition satisfied",
                    "result_status": "UNCOMPROMISED",
                    "is_compromised": False,
                    "live_validated": is_live_validated and live_port_state == "open",
                    "live_host_reachable": live_host_reachable,
                    "live_port_state": (live_port_state.upper() if live_port_state else ("OPEN" if not is_live_validated else "UNKNOWN")),
                    "live_snapshot_used": not (is_live_validated and live_port_state == "open"),
                })
                blocked_failed_paths.append({
                    "source": src_display, "target": dst_display, "decision": "✗ COMPROMISE NOT POSSIBLE",
                    "reason": "No matching vulnerability or sensitive access condition"
                })
                step_counter += 1
                continue

            # ─────────────────────────────────────────────────────────────
            # 5. EVALUATE MODELED PROPAGATION PROBABILITY
            # ─────────────────────────────────────────────────────────────
            if is_honeypot:
                prob = max(0.85, vuln_score)
            else:
                base_prob = edge.get("success_prob", 0.45) * vuln_score * global_dampener
                if dst_data.get("criticality", 1) >= 4:
                    base_prob *= 0.85
                prob = min(0.95, max(0.05, base_prob))

            success = (random.random() < prob)
            actual_timestep = timestep + 1

            if success:
                compromised.add(target)
                G.nodes[target]["compromised"] = True
                new_path = current_path + [target]
                attack_paths.append(new_path)
                successful_paths.append({
                    "source": src_display, "source_id": src_asset_id,
                    "target": dst_display, "target_id": dst_asset_id,
                    "path": path_str, "service": access_service, "port": access_port,
                    "technique": f"{technique_code} — {technique_desc}", "probability": prob
                })
                # Add to evaluation queue to continue propagation from this newly compromised asset!
                queue.append((target, actual_timestep, new_path))

                if is_honeypot:
                    honeypot_triggered = True

                did_priv_esc = False
                if dst_data.get("criticality", 1) >= 4 and target not in priv_escalated:
                    priv_escalated.add(target)
                    G.nodes[target]["priv_escalated"] = True
                    did_priv_esc = True
                    timeline.append({
                        "node": target, "from_node": current_node, "timestep": actual_timestep + 1,
                        "mitre_code": "T1068", "mitre_desc": "Privilege Escalation — elevated rights on critical system",
                        "access_vector": "Credential dump / token theft on high-value asset", "success": True,
                        "vuln": vuln_score, "criticality": dst_data.get("criticality", 1),
                        "ntype": dst_ntype, "priv_esc": True,
                    })

                timeline.append({
                    "node": target, "from_node": current_node, "timestep": actual_timestep,
                    "mitre_code": technique_code, "mitre_desc": technique_desc,
                    "access_vector": path_str, "success": True, "vuln": vuln_score,
                    "criticality": dst_data.get("criticality", 1), "ntype": dst_ntype, "priv_esc": did_priv_esc,
                })

                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": path_str,
                    "service": f"{access_service} (TCP {access_port})",
                    "vulnerability": vuln_desc,
                    "technique": f"{technique_code} — {technique_desc}",
                    "decision": "✓ COMPROMISE POSSIBLE",
                    "probability": f"{int(prob * 100)}%",
                    "prob_float": prob,
                    "reason": f"{val_label} | ✓ Attack condition satisfied | ✓ Defense not blocking | ✓ Probability threshold met (P={prob:.2f})",
                    "result_status": "SIMULATED COMPROMISED",
                    "is_compromised": True,
                    "live_validated": is_live_validated and live_port_state == "open",
                    "live_host_reachable": live_host_reachable,
                    "live_port_state": (live_port_state.upper() if live_port_state else ("OPEN" if not is_live_validated else "UNKNOWN")),
                    "live_snapshot_used": not (is_live_validated and live_port_state == "open"),
                })
            else:
                decision_log.append({
                    "step": step_counter,
                    "source": src_display,
                    "source_node": current_node,
                    "source_id": src_asset_id,
                    "target": dst_display,
                    "target_node": target,
                    "target_id": dst_asset_id,
                    "target_ip": dst_ip,
                    "path": path_str,
                    "service": f"{access_service} (TCP {access_port})",
                    "vulnerability": vuln_desc,
                    "technique": f"{technique_code} — {technique_desc}",
                    "decision": "✗ COMPROMISE NOT POSSIBLE",
                    "probability": f"{int(prob * 100)}%",
                    "prob_float": prob,
                    "reason": f"{val_label} | ✗ Modeled attack resisted / probability threshold not met (P={prob:.2f})",
                    "result_status": "UNCOMPROMISED",
                    "is_compromised": False,
                    "live_validated": is_live_validated and live_port_state == "open",
                    "live_host_reachable": live_host_reachable,
                    "live_port_state": (live_port_state.upper() if live_port_state else ("OPEN" if not is_live_validated else "UNKNOWN")),
                    "live_snapshot_used": not (is_live_validated and live_port_state == "open"),
                })
                blocked_failed_paths.append({
                    "source": src_display, "target": dst_display, "decision": "✗ COMPROMISE NOT POSSIBLE",
                    "reason": f"Resisted exploitation attempt (Probability: {int(prob*100)}%)"
                })
                timeline.append({
                    "node": target, "from_node": current_node, "timestep": actual_timestep,
                    "mitre_code": technique_code, "mitre_desc": technique_desc,
                    "access_vector": path_str, "success": False, "vuln": vuln_score,
                    "criticality": dst_data.get("criticality", 1), "ntype": dst_ntype, "priv_esc": False,
                })

            step_counter += 1

    timeline.sort(key=lambda x: x["timestep"])
    uncompromised = set(G.nodes) - compromised
    real_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    real_compromised = [n for n in compromised if G.nodes[n].get("node_type") != "honeypot"]
    critical_reached = [n for n in real_compromised if G.nodes[n].get("criticality", 1) >= 4]
    max_hops = max((len(p) - 1 for p in attack_paths), default=0)

    stats = {
        "systems_controlled": len(real_compromised),
        "total_systems": len(real_nodes),
        "max_lateral_hops": max_hops,
        "privilege_escalations": len(priv_escalated),
        "attack_paths": attack_paths[:10],
        "reachable_from_entry": len(real_compromised),
        "critical_assets_reached": len(critical_reached),
        "decision_log": decision_log,
        "successful_paths": successful_paths,
        "blocked_failed_paths": blocked_failed_paths,
        "uncompromised": uncompromised,
        "live_validation_used": bool(live_validation),
    }

    return timeline, decision_log, compromised, uncompromised, successful_paths, blocked_failed_paths, stats


def simulate_attack(G, entry_node, seed=42, ids_deployed=False, segmentation_applied=False, applied_rules=None, live_validation=None):
    """
    Standard simulation interface delegating directly to the decision-based propagation engine.
    """
    timeline, decision_log, compromised, uncompromised, successful_paths, blocked_failed_paths, stats = simulate_decision_based_propagation(
        G, entry_node, seed=seed, ids_deployed=ids_deployed, segmentation_applied=segmentation_applied,
        applied_rules=applied_rules, live_validation=live_validation
    )
    honeypot_triggered = any(
        entry.get("ntype") == "honeypot" and entry.get("success") for entry in timeline
    )
    return timeline, compromised, honeypot_triggered, stats


# ─────────────────────────────────────────────────────────────────
# MODULE 3: RISK (BLAST RADIUS) ENGINE
# ─────────────────────────────────────────────────────────────────

def calculate_risk(G, compromised_nodes, timeline, honeypot_triggered, attack_stats=None):
    W1, W2, W3 = 0.3, 0.5, 0.2
    total_nodes = len(G.nodes)
    real_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    real_compromised = [n for n in compromised_nodes if G.nodes[n].get("node_type") != "honeypot"]

    spread = min(1.0, len(real_compromised) / max(len(real_nodes), 1))
    all_criticality = sum(G.nodes[n]["criticality"] for n in real_nodes)
    compromised_criticality = sum(G.nodes[n]["criticality"] for n in real_compromised)
    critical_impact = min(1.0, compromised_criticality / max(all_criticality, 1))

    max_timestep = max((t["timestep"] for t in timeline), default=1)
    depth = min(1.0, max_timestep / max(total_nodes, 1))

    R = (W1 * spread) + (W2 * critical_impact) + (W3 * depth)
    risk_score = R * 100
    if honeypot_triggered:
        risk_score += 15
    risk_score = max(0.0, min(100.0, risk_score))

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
    """Priority 15 / Sprint 2 Phase 3: OVERALL ACDS RISK.

    Keeps Asset Risk (per-host, Priority 6), the Blast-Radius Simulation
    (Module 3), Critical Asset Exposure, and Network Exposure (Sprint 2
    Phase 2, core/network_exposure.py) as four SEPARATE internal concepts,
    then combines them with a documented, non-industry-standard
    aggregation:

        Overall ACDS Risk = Average Asset Risk        * 0.40
                           + Network Blast Radius       * 0.30
                           + Critical Asset Exposure     * 0.15
                           + Network Exposure            * 0.15

    Average Asset Risk = mean of all real (non-honeypot) assets'
    Priority-6 risk_score values. Critical Asset Exposure and Network
    Exposure both come from core/network_exposure.py, which derives them
    from the live exposure-graph topology (Phase 2) — not observed traffic.

    If no simulation has been run yet, blast_radius_score is None and this
    returns a PARTIAL result rather than inventing a blast-radius number.
    """
    real_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") != "honeypot"]
    asset_scores = [G.nodes[n].get("risk_score", 0.0) for n in real_nodes]
    asset_component = round(sum(asset_scores) / len(asset_scores), 1) if asset_scores else 0.0

    critical_exposure = network_exposure.calculate_critical_asset_exposure(G)
    network_component = network_exposure.calculate_network_exposure_component(G)

    weighted_partial = (
        asset_component * OVERALL_WEIGHT_ASSET_RISK
        + critical_exposure['score'] * OVERALL_WEIGHT_CRITICAL_EXPOSURE
        + network_component['score'] * OVERALL_WEIGHT_NETWORK_EXPOSURE
    )

    if blast_radius_score is None:
        return {
            'status': 'PARTIAL — SIMULATION NOT RUN',
            'overall_score': None, 'severity': None,
            'asset_component': asset_component, 'asset_weight': OVERALL_WEIGHT_ASSET_RISK,
            'blast_component': None, 'blast_weight': OVERALL_WEIGHT_BLAST_RADIUS,
            'critical_exposure_component': critical_exposure['score'],
            'critical_exposure_weight': OVERALL_WEIGHT_CRITICAL_EXPOSURE,
            'critical_exposure_detail': critical_exposure,
            'network_exposure_component': network_component['score'],
            'network_exposure_weight': OVERALL_WEIGHT_NETWORK_EXPOSURE,
            'network_exposure_detail': network_component,
        }

    overall = round(weighted_partial + blast_radius_score * OVERALL_WEIGHT_BLAST_RADIUS, 1)
    overall = max(0.0, min(100.0, overall))
    return {
        'status': 'COMPLETE',
        'overall_score': overall, 'severity': severity_from_score(overall),
        'asset_component': asset_component, 'asset_weight': OVERALL_WEIGHT_ASSET_RISK,
        'blast_component': blast_radius_score, 'blast_weight': OVERALL_WEIGHT_BLAST_RADIUS,
        'critical_exposure_component': critical_exposure['score'],
        'critical_exposure_weight': OVERALL_WEIGHT_CRITICAL_EXPOSURE,
        'critical_exposure_detail': critical_exposure,
        'network_exposure_component': network_component['score'],
        'network_exposure_weight': OVERALL_WEIGHT_NETWORK_EXPOSURE,
        'network_exposure_detail': network_component,
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
                "mitre_tactic": "Initial Access / Exploitation for Privilege Escalation — T1190, T1068",
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
                "mitre_tactic": "Lateral Movement — T1021 (Remote Services)",
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
                "mitre_tactic": "Privilege Escalation / Persistence — T1078 (Valid Accounts)",
            })

        # Sprint 3 — Phase 1: port/service-specific hardening actions so the
        # optimizer can recommend the exact SME-facing controls the sprint
        # asked for (disable SMB, restrict RDP, close unused ports), derived
        # from THIS node's actually-observed open_ports — never invented.
        open_ports = nd.get("open_ports", []) or []

        if 445 in open_ports:
            key = f"SMB: {node}"
            if key not in seen_fixes:
                seen_fixes.add(key)
                smb_cost = int(14 + crit * 3)
                smb_reduction = round(max(vuln, 1) * crit * 2.0, 1)
                actions.append({
                    "action": f"Disable SMB on {display[:30]}", "node": node, "type": "disable_smb",
                    "cost": smb_cost, "risk_reduction": smb_reduction,
                    "efficiency": round(smb_reduction / smb_cost, 3),
                    "description": f"Disable SMBv1/legacy SMB (port 445) or restrict it to trusted hosts on {display}",
                    "state": DEFENSE_STATE_RECOMMENDED,
                    "mitre_tactic": "Lateral Movement — T1021.002 (SMB/Windows Admin Shares)",
                })

        if 3389 in open_ports:
            key = f"RDP: {node}"
            if key not in seen_fixes:
                seen_fixes.add(key)
                rdp_cost = int(14 + crit * 3)
                rdp_reduction = round(max(vuln, 1) * crit * 2.0, 1)
                actions.append({
                    "action": f"Restrict RDP on {display[:30]}", "node": node, "type": "restrict_rdp",
                    "cost": rdp_cost, "risk_reduction": rdp_reduction,
                    "efficiency": round(rdp_reduction / rdp_cost, 3),
                    "description": f"Restrict RDP (port 3389) to a VPN/jump-host and enforce MFA on {display}",
                    "state": DEFENSE_STATE_RECOMMENDED,
                    "mitre_tactic": "Lateral Movement — T1021.001 (Remote Desktop Protocol)",
                })

        other_sensitive = [p for p in open_ports if p in SENSITIVE_PORTS and p not in (445, 3389)]
        for port in other_sensitive[:2]:
            key = f"CLOSEPORT: {node}:{port}"
            if key in seen_fixes:
                continue
            seen_fixes.add(key)
            svc_name = PORT_SERVICE_MAP.get(port, f"port {port}")
            close_cost = int(8 + crit * 2)
            close_reduction = round(max(vuln, 1) * 1.6, 1)
            actions.append({
                "action": f"Close unused port {port} ({svc_name}) on {display[:24]}",
                "node": node, "type": "close_port", "cost": close_cost,
                "risk_reduction": close_reduction,
                "efficiency": round(close_reduction / close_cost, 3),
                "description": f"Close or firewall unused {svc_name} service (port {port}) exposed on {display}",
                "state": DEFENSE_STATE_RECOMMENDED,
                "mitre_tactic": "Initial Access — T1190 (Exploit Public-Facing Application) / attack-surface reduction",
            })

    ids_cost = 30
    ids_reduction = round(risk_score * 0.12, 1)
    actions.append({
        "action": "Deploy Network IDS / SIEM", "node": "ALL", "type": "ids",
        "cost": ids_cost, "risk_reduction": ids_reduction,
        "efficiency": round(ids_reduction / ids_cost, 3),
        "description": "Detect lateral movement (Snort/Suricata/Wazuh) across the LAN",
        "state": DEFENSE_STATE_RECOMMENDED,
        "mitre_tactic": "Discovery / Lateral Movement — T1046, T1021 (detection coverage)",
    })

    segment_cost = 25
    segment_reduction = round(risk_score * 0.15, 1)
    actions.append({
        "action": "Network Segmentation (VLANs)", "node": "ALL", "type": "isolate",
        "cost": segment_cost, "risk_reduction": segment_reduction,
        "efficiency": round(segment_reduction / segment_cost, 3),
        "description": "Split workstations, servers, and databases into separate VLANs with ACLs",
        "state": DEFENSE_STATE_RECOMMENDED,
        "mitre_tactic": "Lateral Movement — T1021 (containment via network segmentation)",
    })

    firewall_cost = 20
    firewall_reduction = round(risk_score * 0.10, 1)
    actions.append({
        "action": "Deploy Perimeter Firewall Rules", "node": "ALL", "type": "firewall_rule",
        "cost": firewall_cost, "risk_reduction": firewall_reduction,
        "efficiency": round(firewall_reduction / firewall_cost, 3),
        "description": "Add default-deny inbound/outbound ACLs at the network edge and between segments",
        "state": DEFENSE_STATE_RECOMMENDED,
        "mitre_tactic": "Command and Control / Lateral Movement — network filtering (all tactics)",
    })

    # Honeypot placement: recommend a decoy near the single highest-value
    # reachable critical asset, rather than duplicating the existing
    # simulated Honeypot node already present in the topology.
    candidate_nodes = [n for n in compromised_nodes if G.nodes[n].get("node_type") != "honeypot"]
    if candidate_nodes:
        top_node = max(candidate_nodes, key=lambda n: G.nodes[n].get("criticality", 0))
        top_nd = G.nodes[top_node]
        if top_nd.get("criticality", 0) >= 4:
            hp_cost = 22
            hp_reduction = round(top_nd.get("criticality", 4) * 1.8, 1)
            actions.append({
                "action": f"Honeypot Placement near {top_nd.get('display_name', top_node)[:30]}",
                "node": top_node, "type": "honeypot_placement", "cost": hp_cost,
                "risk_reduction": hp_reduction,
                "efficiency": round(hp_reduction / hp_cost, 3),
                "description": f"Deploy an additional decoy adjacent to {top_nd.get('display_name', top_node)} to "
                                f"detect lateral movement toward this critical asset earlier",
                "state": DEFENSE_STATE_RECOMMENDED,
                "mitre_tactic": "Detection — deception layer supporting earlier Discovery/Lateral Movement alerts",
            })

    # Priority ranking (Sprint 3 requirement): relative to this action set's
    # own risk_reduction distribution — top third HIGH, middle third MEDIUM,
    # bottom third LOW. Recomputed every call, so it always reflects the
    # CURRENT network/compromise state rather than a fixed threshold.
    if actions:
        ranked = sorted(actions, key=lambda a: a["risk_reduction"], reverse=True)
        n = len(ranked)
        high_cut = max(1, n // 3)
        med_cut = max(high_cut + 1, (2 * n) // 3)
        for i, a in enumerate(ranked):
            a["priority"] = "HIGH" if i < high_cut else ("MEDIUM" if i < med_cut else "LOW")

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
        elif atype in ("isolate", "firewall_rule") and node == "ALL":
            # Both VLAN segmentation and perimeter firewall rules reduce the
            # same modeled quantity — lateral-movement reachability — so
            # both feed the existing segmentation_applied flag consumed by
            # simulate_attack(); this is a deliberate simplification, not a
            # rewrite of the attack-simulation engine.
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
            elif atype in ("disable_smb", "restrict_rdp", "close_port"):
                # Remove the specific hardened port from this node's exposed
                # surface so the exposure graph / lateral-edge model and the
                # network_exposure component genuinely reflect the change.
                port_map = {"disable_smb": 445, "restrict_rdp": 3389}
                port_to_close = port_map.get(atype)
                if port_to_close is None:
                    m = re.search(r"port (\d+)", action.get("action", ""))
                    port_to_close = int(m.group(1)) if m else None
                if port_to_close and port_to_close in (nd.get("open_ports") or []):
                    nd["open_ports"] = [p for p in nd["open_ports"] if p != port_to_close]
                if comps:
                    comps['network_exposure']['normalized_score'] = round(
                        comps['network_exposure']['normalized_score'] * 0.5, 1)
                    recompute_node_risk(nd)
            elif atype == "honeypot_placement" and comps:
                # A nearby decoy shortens detection time rather than closing
                # an exposure, modeled as a modest deterrent discount on the
                # vulnerability component (attacker more likely caught early).
                comps['vulnerability']['normalized_score'] = round(
                    comps['vulnerability']['normalized_score'] * 0.8, 1)
                recompute_node_risk(nd)

        applied.append({**action, "state": DEFENSE_STATE_APPLIED})

    return applied, ids_deployed, segmentation_applied


# ─────────────────────────────────────────────────────────────────
# SPRINT 3 — PHASE 2: DEDICATED BEFORE vs AFTER VERIFICATION PAGE
# ─────────────────────────────────────────────────────────────────
# Renders a standalone comparison section (Overall Risk, Blast Radius,
# Critical Assets Reachable, Attack Depth, Reachable Nodes) using ONLY
# numbers already produced by the existing Sprint 2 risk pipeline
# (calculate_risk / calculate_overall_acds_risk / simulate_attack) —
# no separate/duplicate risk math is introduced here.

def _verification_metric_row(rows):
    """rows: list of (label, before_val, after_val_or_None, lower_is_better)."""
    cards = []
    for label, before_val, after_val, lower_is_better in rows:
        if after_val is None:
            cards.append(f"""
            <div style='flex:1;min-width:150px;background:#0d1f2d;border:1px solid #1a3a5c;padding:14px;text-align:center'>
                <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.62rem;letter-spacing:1px'>{label}</div>
                <div style='color:#ffd700;font-family:Orbitron,monospace;font-size:1.3rem;margin-top:4px'>{before_val}</div>
                <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.6rem;margin-top:2px'>defenses not yet applied</div>
            </div>""")
            continue
        delta = round(after_val - before_val, 1)
        improved = (delta <= 0) if lower_is_better else (delta >= 0)
        arrow_color = "#00ff88" if improved else "#ff3355"
        delta_str = f"{'+' if delta > 0 else ''}{delta}"
        cards.append(f"""
        <div style='flex:1;min-width:150px;background:#0d1f2d;border:1px solid {arrow_color};padding:14px;text-align:center'>
            <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.62rem;letter-spacing:1px'>{label}</div>
            <div style='font-family:Orbitron,monospace;font-size:1.25rem;margin-top:4px'>
                <span style='color:#ff3355'>{before_val}</span>
                <span style='color:#3d6a8a;font-size:0.9rem'> → </span>
                <span style='color:#00ff88'>{after_val}</span>
            </div>
            <div style='color:{arrow_color};font-family:Share Tech Mono;font-size:0.72rem;margin-top:4px'>{delta_str} points</div>
        </div>""")
    return "<div style='display:flex;gap:10px;flex-wrap:wrap;margin:10px 0'>" + "".join(cards) + "</div>"


def render_before_after_verification():
    before_overall = st.session_state.overall_acds_risk_before
    before_bd = st.session_state.blast_before_defense or {}
    before_risk = st.session_state.risk_before_defense

    has_after = bool(st.session_state.applied_defenses)
    after_overall_obj = st.session_state.overall_acds_risk if has_after else None
    after_bd = st.session_state.post_defense_stats if has_after else None
    after_risk = st.session_state.risk_score if has_after else None

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)
    st.markdown('<div class="section-header">🎯 BEFORE vs AFTER VERIFICATION</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style='background:rgba(255,51,85,0.06);border:1px solid #ff3355;padding:8px 14px;
         font-family:Share Tech Mono;font-size:0.65rem;color:#ff3355;letter-spacing:1px;margin-bottom:10px'>
    SIMULATED — NO REAL ATTACK TRAFFIC
    </div>
    """, unsafe_allow_html=True)

    if before_risk is None:
        st.markdown(
            '<div style="font-family:Share Tech Mono;font-size:0.72rem;color:#3d6a8a">'
            'Run an attack simulation to establish a BEFORE snapshot for verification.</div>',
            unsafe_allow_html=True)
        return

    before_overall_score = before_overall.get("overall_score") if before_overall else None
    after_overall_score = after_overall_obj.get("overall_score") if after_overall_obj else None

    rows = [
        ("OVERALL RISK", before_overall_score, after_overall_score, True),
        ("BLAST RADIUS", before_risk, after_risk, True),
        ("CRITICAL ASSETS REACHABLE", before_bd.get("critical_assets_reached", 0),
         after_bd.get("critical_assets_reached", 0) if after_bd else None, True),
        ("ATTACK DEPTH (hops)", before_bd.get("max_lateral_hops", 0),
         after_bd.get("max_lateral_hops", 0) if after_bd else None, True),
        ("REACHABLE NODES", before_bd.get("systems_controlled", before_bd.get("compromised_count", 0)),
         (after_bd.get("systems_controlled", after_bd.get("compromised_count", 0)) if after_bd else None), True),
    ]
    # Drop rows where before_val itself is None (overall risk not yet complete)
    rows = [r for r in rows if r[1] is not None]
    st.markdown(_verification_metric_row(rows), unsafe_allow_html=True)

    if not has_after:
        st.markdown(
            '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a;margin-top:6px">'
            'Apply defenses in the ACDS DEFENSE OPTIMIZATION panel above, then this page re-runs the MITRE '
            'simulation automatically against the validated network posture and fills in the AFTER column.</div>', unsafe_allow_html=True)
    else:
        # Verified Real-Time Defense Card
        val_changes = st.session_state.get("validation_changes", [])
        verified_changes = [c for c in val_changes if "REMOVED" in c.get("change_type", "") or "VERIFIED" in c.get("change_type", "")]

        if verified_changes:
            v_items = "".join(f"<li><b>{c.get('change_type')}:</b> {c.get('description')}</li>" for c in verified_changes[:4])
            st.markdown(f"""
            <div style='background:rgba(0,255,136,0.06);border:1px solid #00ff88;border-left:4px solid #00ff88;padding:12px 16px;border-radius:4px;margin:14px 0'>
                <div style='color:#00ff88;font-family:Orbitron,monospace;font-size:0.8rem;font-weight:bold'>
                    ✓ REAL-TIME DEFENSE RE-VALIDATION CONFIRMED
                </div>
                <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#e0f4ff;margin-top:4px'>
                    Real-time network validation confirms that targeted attack surface ports are CLOSED and verified non-responsive:
                    <ul style='margin:4px 0 0 16px;color:#7ab8d4'>{v_items}</ul>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div style="font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;margin:14px 0 6px 0">'
                     'MITRE ATT&CK COVERAGE — BEFORE vs AFTER (re-simulated)</div>', unsafe_allow_html=True)
        before_mitre = st.session_state.mitre_before_defense or {}
        after_mitre = st.session_state.mitre_after_defense or {}
        mcol1, mcol2 = st.columns(2)
        with mcol1:
            st.markdown("<div style='color:#ff3355;font-family:Share Tech Mono;font-size:0.68rem'>BEFORE</div>", unsafe_allow_html=True)
            if before_mitre:
                for code, desc in before_mitre.items():
                    st.markdown(f'<span class="mitre-tag">{code}</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span style="color:#3d6a8a;font-size:0.68rem">none reached</span>', unsafe_allow_html=True)
        with mcol2:
            st.markdown("<div style='color:#00ff88;font-family:Share Tech Mono;font-size:0.68rem'>AFTER</div>", unsafe_allow_html=True)
            if after_mitre:
                for code, desc in after_mitre.items():
                    st.markdown(f'<span class="mitre-tag" style="border-color:#00ff88;color:#00ff88">{code}</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span style="color:#00ff88;font-size:0.68rem">none reached — all techniques blocked</span>', unsafe_allow_html=True)

        mitigated = set(before_mitre) - set(after_mitre)
        if mitigated:
            st.markdown(
                f'<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin-top:8px">'
                f'Techniques neutralized by applied defenses: {", ".join(sorted(mitigated))}</div>',
                unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# MODULE 5: ASSET INTELLIGENCE & GRAPH VISUALIZATION ENGINE
# ─────────────────────────────────────────────────────────────────

def _evidence_block(title, evidence_list, color="#3d6a8a"):
    if not evidence_list:
        return ""
    items = "".join(f"<div>✓ {html_lib.escape(str(e))}</div>" for e in evidence_list[:4])
    return f"<div style='margin:2px 0 6px 70px;font-size:0.62rem;color:{color};line-height:1.6'>{items}</div>"

def render_node_panel(active_node=None, selected_node=None, G=None):
    if G is None:
        G = st.session_state.G
    html = ""
    for node, data in G.nodes(data=True):
        if selected_node and node != selected_node:
            continue
        is_comp = data.get("compromised", False)
        ntype = data.get("node_type", "endpoint")
        is_honey = ntype == "honeypot"
        is_active = node == active_node
        is_isolated = data.get("isolated", False)

        card_class = "compromised" if is_comp else "honeypot" if is_honey else "safe"
        if is_active:
            card_class = "compromised"

        status_icon = ("🔴 COMPROMISED (simulated)" if is_comp else
                        "🟢 ISOLATED (defense applied)" if is_isolated else
                        "⚠ ALERT" if (is_honey and st.session_state.get("honeypot_triggered", False)) else
                        "🟡 DECOY" if is_honey else "🔵 OBSERVED SECURE")
        if is_active:
            status_icon = "💥 UNDER SIMULATED ATTACK"

        crit_label = data.get('criticality_label', 'Unknown')
        crit_val = data.get("criticality", 1)
        crit_stars = "★" * crit_val + "☆" * (5 - crit_val)
        crit_conf = data.get('criticality_confidence')
        conf_str = f" ({int(crit_conf*100)}% confidence)" if isinstance(crit_conf, (int, float)) else ""

        ip = data.get('ip', '')
        hostname = data.get('hostname', '')
        mac_addr = data.get('mac') or data.get('mac_address') or ''
        asset_id = data.get('asset_id') or generate_asset_id(mac_addr, ip, hostname, data.get('mac_vendor'), data.get('os'))
        prev_ips = data.get('previous_ips') or []
        if isinstance(prev_ips, str):
            try:
                prev_ips = json.loads(prev_ips)
            except Exception:
                prev_ips = [prev_ips] if prev_ips else []
        lifecycle_status = data.get('lifecycle_status')
        if not lifecycle_status and prev_ips:
            lifecycle_status = "IP_CHANGED"

        asset_id_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>Asset ID:</span><span style='color:#00ff88;font-family:Share Tech Mono,monospace;font-weight:bold'>{asset_id}</span></div>" if asset_id else ""
        lifecycle_badge = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#ffaa33;width:105px'>State:</span><span style='background:rgba(255,170,51,0.12);border:1px solid #ffaa33;color:#ffaa33;padding:2px 6px;border-radius:3px;font-size:0.65rem;font-weight:bold'>🔄 SAME DEVICE — IP CHANGED</span></div>" if (lifecycle_status == "IP_CHANGED" or prev_ips) else ""
        prev_ips_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>Previous IP(s):</span><span style='color:#7ab8d4;font-family:Share Tech Mono,monospace'>{', '.join(prev_ips)}</span></div>" if prev_ips else ""
        mac_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>MAC Address:</span><span style='color:#e0f4ff;font-family:Share Tech Mono,monospace'>{mac_addr}</span></div>" if mac_addr else ""
        hostname_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>Hostname:</span><span style='color:#e0f4ff'>{hostname}</span></div>" if hostname else ""

        os_type = data.get('os', 'unknown')
        os_confidence = data.get('os_confidence')
        os_evidence = data.get('os_evidence') or []
        os_icon = {'windows': '🪟', 'linux': '🐧', 'macos': '🍎', 'ios': '📱', 'android': '🤖', 'unknown': '❓'}.get(os_type.lower(), '❓')
        conf_suffix = f" · {int(round(os_confidence * 100))}% confidence" if isinstance(os_confidence, (int, float)) else ""
        os_label = {'windows': 'Windows', 'linux': 'Linux', 'macos': 'macOS', 'ios': 'iOS', 'android': 'Android'}.get(os_type.lower(), os_type.upper() if os_type else 'Unknown')
        os_html = (
            f"<div style='display:flex;align-items:center;margin:4px 0'>"
            f"<span style='color:#3d6a8a;width:105px'>Inferred OS:</span>"
            f"<span style='color:#e0f4ff'>{os_icon} {os_label}{conf_suffix}</span></div>"
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
            'Mac Computer': '🍎', 'Decoy System': '🍯',
        }.get(device_type, '💻' if os_type == 'windows' else '🖥️' if os_type == 'linux' else '📦')
        vendor_suffix = f" ({vendor})" if vendor else ""
        device_html = (
            f"<div style='display:flex;align-items:center;margin:4px 0'>"
            f"<span style='color:#3d6a8a;width:105px'>Inferred Device:</span>"
            f"<span style='color:#e0f4ff'>{device_icon} {device_type or 'Network Host'}{vendor_suffix}{dconf_str}</span>"
            f"</div>" + _evidence_block("", device_evidence)
        )

        version_map = data.get('version_map', {})
        services = data.get('services', [])
        if version_map:
            svc_strs = [f"{s} ({version_map[s]})" if version_map.get(s) else s for s in services[:4]]
        else:
            svc_strs = services[:4]
        services_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>Services:</span><span style='color:#e0f4ff'>{', '.join(svc_strs)}{'...' if len(services) > 4 else ''}</span></div>" if services else ""
        open_ports = data.get('open_ports', [])
        ports_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>Ports:</span><span style='color:#e0f4ff'>{', '.join(str(p) for p in open_ports) or 'None detected'}</span></div>"

        risk_score = data.get('risk_score', int(data.get('vulnerability', 0) * 100))
        risk_severity = data.get('risk_severity', 'LOW')
        comps = data.get('risk_components') or {}

        def comp_row(key, label, cap):
            c = comps.get(key, {})
            contrib = c.get('contribution', 0)
            return f"<div style='display:flex;justify-content:space-between;color:#7ab8d4;margin:2px 0;'><span>{label}</span><span style='color:#e0f4ff'>{contrib:.1f} / {cap}</span></div>"

        risk_breakdown_html = ""
        if comps:
            risk_breakdown_html = (
                "<div style='margin:6px 0;padding:8px 10px;background:rgba(0,212,255,0.04);border:1px solid #1a3a5c;border-radius:4px;font-size:0.65rem'>"
                "<div style='color:#00d4ff;font-weight:bold;margin-bottom:6px;letter-spacing:1px'>RISK CALCULATION BREAKDOWN</div>"
                + comp_row('vulnerability', 'Vulnerability / CVSS', 40)
                + comp_row('service_exposure', 'Service Exposure', 20)
                + comp_row('sensitive_services', 'Sensitive Services', 15)
                + comp_row('criticality', 'Asset Criticality', 15)
                + comp_row('network_exposure', 'Network Exposure', 10)
                + f"<div style='border-top:1px solid #1a3a5c;margin-top:6px;padding-top:4px;display:flex;justify-content:space-between;color:#00d4ff;font-weight:bold'><span>TOTAL SCORE</span><span style='color:#00ff88'>{risk_score} / 100</span></div>"
                "</div>"
            )
        risk_color = "#ff3355" if risk_score > 70 else "#ff8c00" if risk_score > 40 else "#00ff88"
        risk_html = (
            f"<div style='margin:6px 0;padding:6px 10px;background:rgba(0,212,255,0.05);border-left:3px solid {risk_color};border-radius:2px'>"
            f"<div style='color:{risk_color};font-size:0.72rem;font-weight:bold;'>ASSET RISK: {risk_score}/100 — {risk_severity}</div></div>"
            + risk_breakdown_html
        )

        sensitive_detected = (data.get('asset_risk') or {}).get('sensitive_detected', [])
        sensitive_html = ""
        if sensitive_detected:
            sens_strs = [f"{s[0]} ({s[1]})" if isinstance(s, (list, tuple)) and len(s) >= 2 else str(s) for s in sensitive_detected]
            sensitive_html = (
                f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>Sensitive:</span>"
                f"<span style='color:#ff3355'>{', '.join(sens_strs)}</span></div>"
            )

        cve_findings = data.get('cve_findings', [])
        cve_html = ""
        if cve_findings:
            cve_badges = "".join(
                f"<span class='cve-tag' title='{c.get('summary','')[:80]}'>{c['cve_id']} (CVSS {c['cvss']})</span>"
                for c in cve_findings[:4]
            )
            cve_html = f"<div style='margin:4px 0'><div style='color:#3d6a8a;font-size:0.65rem;margin-bottom:2px'>MATCHED CVEs:</div>{cve_badges}</div>"

        fixes = data.get('fixes', [])
        recommendation_html = ""
        if fixes:
            recommendation_html = "".join(f"<div style='color:#00ff88;font-size:0.65rem;margin:2px 0;'>• {fix}</div>" for fix in fixes[:3])
            recommendation_html = f"<div style='margin:6px 0;padding:8px 10px;background:rgba(0,255,136,0.04);border:1px solid #1a3a5c;border-left:3px solid #00ff88;border-radius:4px'><div style='color:#00ff88;font-size:0.65rem;font-weight:bold;margin-bottom:4px'>RECOMMENDED ACTIONS</div>{recommendation_html}</div>"

        node_color = "#ff3355" if is_comp else "#00ff88" if is_isolated else "#ffd700" if is_honey else "#00d4ff"
        disp_title = data.get('display_name', node)
        html += (
            f"<div class='node-card {card_class}'>"
            f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;border-bottom:1px solid #1a3a5c;padding-bottom:4px'>"
            f"<span style='color:{node_color};font-family:Orbitron,monospace;font-size:0.82rem;font-weight:700'>{disp_title}</span>"
            f"<span style='font-size:0.62rem;opacity:0.9'>{status_icon}</span></div>"
            f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>IP:</span><span style='color:#e0f4ff'>{ip}</span></div>"
            f"{asset_id_html}{lifecycle_badge}{mac_html}{prev_ips_html}{hostname_html}{os_html}{device_html}{ports_html}{services_html}{risk_html}{sensitive_html}{cve_html}{recommendation_html}"
            f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:105px'>Role:</span><span style='color:#e0f4ff'>{data.get('role', 'Node')}</span></div>"
            f"<div style='margin:4px 0'><span style='color:#3d6a8a;width:105px;display:inline-block;'>Criticality:</span><span style='color:#ffd700'>{crit_label}{conf_str} ({crit_stars})</span>"
            + _evidence_block("", data.get('criticality_evidence') or [])
            + "</div></div>"
        )
    return html


def render_graph(G, compromised_set=None, current_node=None, show_honeypot=True, new_exposure_edges=None,
                 edge_filter="Clean View", layout_mode="Force-Directed (Dynamic)"):
    if compromised_set is None:
        compromised_set = set()
    new_exposure_edges = new_exposure_edges or set()
    num_nodes = len(G.nodes)

    net = Network(height="570px", width="100%", bgcolor="#050a0f", font_color="#7ab8d4", directed=True)

    if layout_mode == "Hierarchical (Tiered)":
        layout_json = """
        "layout": {
            "hierarchical": {
                "enabled": true,
                "direction": "UD",
                "sortMethod": "directed",
                "nodeSpacing": 180,
                "levelSeparation": 140
            }
        },
        "physics": { "enabled": false }
        """
    else:
        spring_len = max(180, min(360, 160 + num_nodes * 6))
        grav_const = min(-120, -50 - num_nodes * 6)
        layout_json = f"""
        "physics": {{
            "enabled": true,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {{
                "gravitationalConstant": {grav_const},
                "centralGravity": 0.008,
                "springLength": {spring_len},
                "springConstant": 0.04,
                "damping": 0.45,
                "avoidOverlap": 1.0
            }},
            "stabilization": {{
                "enabled": true,
                "iterations": 180,
                "updateInterval": 25
            }}
        }}
        """

    options_str = f"""
    {{
      "nodes": {{
          "borderWidth": 2,
          "shadow": {{"enabled": true, "size": 10, "color": "rgba(0,0,0,0.7)"}},
          "font": {{
              "size": 11,
              "face": "Share Tech Mono, Segoe UI, monospace",
              "color": "#e0f4ff",
              "strokeWidth": 3,
              "strokeColor": "#050a0f"
          }}
      }},
      "edges": {{
          "smooth": {{"type": "curvedCW", "roundness": 0.12}},
          "shadow": {{"enabled": false}},
          "selectionWidth": 2.2,
          "hoverWidth": 1.6
      }},
      {layout_json},
      "interaction": {{
          "hover": true,
          "hoverConnectedEdges": true,
          "selectConnectedEdges": true,
          "multiselect": false,
          "tooltipDelay": 70,
          "zoomView": true,
          "navigationButtons": true,
          "keyboard": true,
          "dragNodes": true
      }}
    }}
    """
    net.set_options(options_str)

    type_shapes = {"perimeter": "diamond", "endpoint": "dot", "server": "square",
                   "database": "database", "honeypot": "star"}
    level_map = {"perimeter": 1, "endpoint": 2, "server": 3, "database": 4, "honeypot": 2}

    for node, data in G.nodes(data=True):
        ntype = data.get("node_type", "endpoint")
        is_compromised = node in compromised_set
        is_current = node == current_node
        is_honeypot = ntype == "honeypot"
        is_isolated = data.get("isolated", False)
        if not show_honeypot and is_honeypot:
            continue

        if is_current:
            color = {"background": "#ff8c00", "border": "#ffd700", "highlight": {"background": "#ffaa33", "border": "#ffffff"}}
            size = 30
        elif is_compromised and is_honeypot:
            color = {"background": "#ff3355", "border": "#ffd700", "highlight": {"background": "#ff5577", "border": "#ffffff"}}
            size = 28
        elif is_compromised:
            color = {"background": "#6b0018", "border": "#ff3355", "highlight": {"background": "#cc0033", "border": "#ffffff"}}
            size = 26
        elif is_honeypot:
            color = {"background": "#3d2800", "border": "#ffd700", "highlight": {"background": "#5a3d00", "border": "#ffd700"}}
            size = 22
        elif is_isolated:
            color = {"background": "#0a2e1a", "border": "#00ff88", "highlight": {"background": "#0f3d22", "border": "#00ff88"}}
            size = 22
        elif ntype in ("server", "database"):
            color = {"background": "#0b3050", "border": "#00d4ff", "highlight": {"background": "#144e80", "border": "#00ffff"}}
            size = 26
        else:
            color = {"background": "#002035", "border": "#00a8cc", "highlight": {"background": "#003d60", "border": "#00ffff"}}
            size = 20

        ip = data.get('ip', '')
        hostname = data.get('hostname', '')
        role = data.get('role', 'Node')
        os_type = data.get('os', '')
        os_label = {'ios': 'iOS', 'android': 'Android', 'macos': 'macOS', 'windows': 'Windows', 'linux': 'Linux'}.get(os_type.lower(), os_type.upper() if os_type else 'Unknown')
        crit = data.get('criticality', 1)
        cves = data.get('cve_findings', [])
        cve_html = ''.join(f"CONFIRMED: {c['cve_id']} (CVSS {c['cvss']})<br>" for c in cves[:2])
        status_label = ('🔴 COMPROMISED (simulated)' if is_compromised else
                         '🟢 ISOLATED (defense applied)' if is_isolated else
                         '🟡 HONEYPOT (decoy)' if is_honeypot else '🔵 OBSERVED ASSET')

        tooltip = (
            f"<div style='font-family:Share Tech Mono,Segoe UI,monospace;font-size:11px;color:#e0f4ff;background:#09141f;padding:9px 12px;border:1px solid #00d4ff;border-radius:4px;box-shadow:0 4px 15px rgba(0,0,0,0.85);line-height:1.45'>"
            f"<b style='color:#00d4ff;font-size:12px'>{data.get('display_name', node)}</b><br>"
            f"<b>IP:</b> {ip}<br>"
            f"<b>Inferred OS:</b> {os_label}<br>"
            f"<b>Role:</b> {role} ({data.get('device_type') or 'Network Host'})<br>"
            f"<b>Criticality:</b> {data.get('criticality_label','?')} ({'★' * crit})<br>"
            f"<b>Asset Risk:</b> {data.get('risk_score', int(data.get('vulnerability',0)*100))}/100 ({data.get('risk_severity','?')})<br>"
            f"<b>Open Ports:</b> {', '.join(str(p) for p in data.get('open_ports', [])) or 'None'}<br>"
            f"{cve_html}"
            f"<b>Status:</b> {status_label}</div>"
        )

        if hostname and hostname.lower() not in ('unknown', 'none', ip.lower()):
            clean_name = hostname if len(hostname) <= 15 else f"{hostname[:13]}…"
            short_label = f"{clean_name}\n{ip}"
        else:
            short_label = f"{role}\n{ip}"

        node_kwargs = {
            'label': short_label,
            'title': tooltip,
            'color': color,
            'size': size,
            'shape': type_shapes.get(ntype, "dot"),
        }
        if layout_mode == "Hierarchical (Tiered)":
            node_kwargs['level'] = level_map.get(ntype, 2)

        net.add_node(node, **node_kwargs)

    for src, dst, data in G.edges(data=True):
        if not show_honeypot and (G.nodes[src].get("node_type") == "honeypot" or G.nodes[dst].get("node_type") == "honeypot"):
            continue

        src_data = G.nodes[src]
        dst_data = G.nodes[dst]
        src_comp = src in compromised_set
        dst_comp = dst in compromised_set
        src_ip = src_data.get('ip')
        dst_ip = dst_data.get('ip')

        is_new_exposure = (src_ip, dst_ip) in new_exposure_edges
        dst_severity = dst_data.get('risk_severity', 'LOW')
        dst_crit = dst_data.get('criticality', 1)
        src_type = src_data.get('node_type', 'endpoint')
        dst_type = dst_data.get('node_type', 'endpoint')

        is_attack_path = src_comp and dst_comp
        is_active_sim = src_comp and not dst_comp
        is_high_risk = dst_severity in ("CRITICAL", "HIGH") or dst_crit >= 4
        is_infra_target = dst_type in ('server', 'database', 'honeypot')
        is_perimeter_source = src_type == 'perimeter'

        if "Clean View" in edge_filter or "Attack Focus" in edge_filter:
            if compromised_set:
                if not (is_attack_path or is_active_sim or is_new_exposure or (is_high_risk and (src_comp or dst_comp))):
                    continue
            else:
                if num_nodes > 6 and not (is_high_risk or is_new_exposure or is_infra_target or is_perimeter_source):
                    continue
        elif "Attack Paths Only" in edge_filter:
            if not (is_attack_path or is_active_sim or is_new_exposure):
                continue
        elif "High-Risk Paths Only" in edge_filter:
            if not (is_attack_path or is_active_sim or is_new_exposure or is_high_risk):
                continue

        if is_attack_path:
            edge_color = {"color": "#ff3355", "highlight": "#ff5577", "hover": "#ffffff", "opacity": 0.95}
            width = 2.8
            arrows = {"to": {"enabled": True, "scaleFactor": 0.55, "type": "arrow"}}
            dashes = False
            edge_note = "SIMULATED ATTACK PATH"
            status_color = "#ff3355"
        elif is_active_sim:
            edge_color = {"color": "#ff8c00", "highlight": "#ffaa33", "hover": "#ffffff", "opacity": 0.9}
            width = 2.0
            arrows = {"to": {"enabled": True, "scaleFactor": 0.5, "type": "arrow"}}
            dashes = [5, 5]
            edge_note = "ACTIVE ATTACK FRONTIER"
            status_color = "#ff8c00"
        elif is_new_exposure:
            edge_color = {"color": "#ffd700", "highlight": "#ffff55", "hover": "#ffffff", "opacity": 0.85}
            width = 1.8
            arrows = {"to": {"enabled": True, "scaleFactor": 0.45, "type": "arrow"}}
            dashes = False
            edge_note = "NEWLY EXPOSED PATH"
            status_color = "#ffd700"
        elif is_high_risk or is_infra_target:
            edge_color = {"color": "rgba(0, 212, 255, 0.45)", "highlight": "#00ffff", "hover": "#00ffff", "opacity": 0.75}
            width = 1.2
            arrows = {"to": {"enabled": True, "scaleFactor": 0.4, "type": "arrow"}}
            dashes = False
            edge_note = "CORE INFRASTRUCTURE REACHABILITY"
            status_color = "#00d4ff"
        else:
            edge_color = {"color": "rgba(45, 95, 140, 0.22)", "highlight": "#00ffff", "hover": "#00ffff", "opacity": 0.35}
            width = 0.8
            arrows = {"to": {"enabled": (num_nodes <= 8), "scaleFactor": 0.35, "type": "arrow"}}
            dashes = False
            edge_note = "POTENTIAL LATERAL REACHABILITY"
            status_color = "#3d6a8a"

        src_disp = src_data.get('display_name', src)
        dst_disp = dst_data.get('display_name', dst)
        conn = data.get('connection', 'LAN')
        vec = data.get('access_vector', 'Network Reachability')
        mitre_code = data.get('mitre_code')
        mitre_desc = data.get('mitre_desc')
        mitre_html = f"<div><span style='color:#7ab8d4;'>MITRE:</span> <span style='color:#ffaa33;'>{mitre_code} — {mitre_desc}</span></div>" if mitre_code else ""

        edge_title = (
            f"<div style='font-family:Share Tech Mono,Segoe UI,monospace;font-size:11px;color:#e0f4ff;background:#09141f;"
            f"padding:8px 12px;border:1px solid #00d4ff;border-radius:4px;box-shadow:0 4px 15px rgba(0,0,0,0.85);line-height:1.45;'>"
            f"<div style='color:#00d4ff;font-weight:bold;font-size:12px;margin-bottom:3px;'>➔ {src_disp} &rarr; {dst_disp}</div>"
            f"<div><span style='color:#7ab8d4;'>Port/Service:</span> <b style='color:#ffffff;'>{conn}</b></div>"
            f"<div><span style='color:#7ab8d4;'>Vector:</span> <span style='color:#00ff88;'>{vec}</span></div>"
            f"{mitre_html}"
            f"<div style='margin-top:4px;padding-top:4px;border-top:1px solid #1a3a5c;color:{status_color};font-weight:bold;font-size:10px;'>● {edge_note}</div>"
            f"</div>"
        )
        net.add_edge(src, dst, title=edge_title, color=edge_color, width=width, arrows=arrows, dashes=dashes)

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

    # Pre-generate full intelligence cards for every node in G
    node_cards = {}
    default_node = None
    max_risk = -1
    for n, d in G.nodes(data=True):
        card_html = render_node_panel(selected_node=n, G=G)
        node_cards[n] = card_html
        r = d.get('risk_score', 0)
        if r > max_risk or default_node is None:
            max_risk = r
            default_node = n

    node_cards_json = json.dumps(node_cards)
    default_node_json = json.dumps(default_node or "")

    # Replace the pyvis card container with side-by-side flex layout (Map on Left, Inspector on Right)
    old_card_pattern = r'<div class="card" style="width: 100%">\s*<div id="mynetwork" class="card-body"></div>\s*</div>'
    side_by_side_html = """
    <div class="hud-side-by-side-container" style="display: flex; flex-direction: row; gap: 14px; width: 100%; height: 570px; box-sizing: border-box; align-items: stretch; margin: 0; padding: 0;">
        <div class="hud-map-panel" style="flex: 1.22; min-width: 0; height: 100%; position: relative; background: #050a0f; border: 1px solid #1a3a5c; border-radius: 6px; overflow: hidden; display: flex; flex-direction: column;">
            <div id="mynetwork" style="width: 100% !important; height: 100% !important; flex: 1; background-color: #050a0f !important; border: none !important;"></div>
        </div>
        <div id="inspector-wrapper" style="flex: 0.98; min-width: 0; height: 100%; overflow-y: auto; background: #071019; border: 1px solid #1a3a5c; border-radius: 6px; padding: 12px 14px; box-sizing: border-box; display: flex; flex-direction: column;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1a3a5c; padding-bottom: 8px; margin-bottom: 10px; flex-shrink: 0;">
                <span style="color: #00d4ff; font-weight: bold; font-size: 0.8rem; letter-spacing: 1px; display: flex; align-items: center; gap: 8px;">
                    <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#00d4ff;box-shadow:0 0 8px #00d4ff;"></span>
                    🔍 ASSET INTELLIGENCE INSPECTOR
                </span>
                <span id="inspector-badge" style="font-size: 0.68rem; color: #00ff88; background: rgba(0,255,136,0.08); padding: 3px 8px; border-radius: 3px; border: 1px solid rgba(0,255,136,0.25);">Click any node in map</span>
            </div>
            <div id="inspector-body" style="font-size: 0.78rem; overflow-y: auto; flex: 1; padding-right: 4px;"></div>
        </div>
    </div>
    """

    if re.search(old_card_pattern, html, flags=re.DOTALL):
        html = re.sub(old_card_pattern, side_by_side_html, html, flags=re.DOTALL)
    elif '<div id="mynetwork"' in html:
        html = re.sub(r'<div id="mynetwork"[^>]*></div>', side_by_side_html, html)

    inspector_injection = f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap');
    #mynetwork {{
        width: 100% !important;
        height: 100% !important;
        background-color: #050a0f !important;
        border: none !important;
        position: relative;
        float: none !important;
    }}
    #inspector-wrapper::-webkit-scrollbar, #inspector-body::-webkit-scrollbar {{
        width: 6px;
    }}
    #inspector-wrapper::-webkit-scrollbar-track, #inspector-body::-webkit-scrollbar-track {{
        background: #050a0f;
    }}
    #inspector-wrapper::-webkit-scrollbar-thumb, #inspector-body::-webkit-scrollbar-thumb {{
        background: #1a3a5c;
        border-radius: 3px;
    }}
    #inspector-wrapper::-webkit-scrollbar-thumb:hover, #inspector-body::-webkit-scrollbar-thumb:hover {{
        background: #00d4ff;
    }}
    .node-card {{
        background: #09141f;
        border: 1px solid #1a3a5c;
        border-left: 3px solid #00d4ff;
        padding: 12px 14px;
        margin: 6px 0;
        font-family: 'Share Tech Mono', Segoe UI, monospace;
        font-size: 0.76rem;
        line-height: 1.7;
        border-radius: 4px;
    }}
    .node-card.safe {{ border-left-color: #00ff88; }}
    .node-card.compromised {{ border-left-color: #ff3355; animation: pulse-red 1.2s infinite; }}
    .node-card.honeypot {{ border-left-color: #ffd700; }}
    @keyframes pulse-red {{
        0%, 100% {{ border-left-color: #ff3355; box-shadow: 0 0 8px rgba(255, 51, 85, 0.3); }}
        50% {{ border-left-color: #ff6680; box-shadow: 0 0 18px rgba(255, 51, 85, 0.5); }}
    }}
    .cve-tag {{
        display: inline-block;
        background: rgba(255, 51, 85, 0.15);
        border: 1px solid #ff3355;
        color: #ff3355;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.65rem;
        padding: 2px 6px;
        margin: 2px;
        border-radius: 3px;
    }}
    .mitre-tag {{
        display: inline-block;
        background: rgba(255, 140, 0, 0.15);
        border: 1px solid #ff8c00;
        color: #ff8c00;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.65rem;
        padding: 2px 6px;
        margin: 2px;
        border-radius: 3px;
    }}
    .risk-bar-container {{
        background: rgba(255,255,255,0.05);
        border: 1px solid #1a3a5c;
        height: 10px;
        border-radius: 2px;
        overflow: hidden;
        margin: 4px 0;
    }}
    .risk-bar {{ height: 100%; transition: width 0.4s ease; border-radius: 2px; }}
    </style>

    <script type="text/javascript">
    (function() {{
        var cards = {node_cards_json};
        var defNode = {default_node_json};
        var badge = document.getElementById("inspector-badge");
        var body = document.getElementById("inspector-body");

        function renderInspector(nodeId) {{
            if (!nodeId || !cards[nodeId]) return;
            var cleanLabel = nodeId.replace(/\\n/g, ' · ');
            if (badge) badge.innerText = "INSPECTING: " + cleanLabel;
            if (body) body.innerHTML = cards[nodeId];
        }}

        if (typeof network !== "undefined") {{
            network.on("selectNode", function(params) {{
                if (params.nodes && params.nodes.length > 0) {{
                    renderInspector(params.nodes[0]);
                }}
            }});
            network.on("click", function(params) {{
                if (params.nodes && params.nodes.length > 0) {{
                    renderInspector(params.nodes[0]);
                }}
            }});
        }}

        if (defNode && cards[defNode]) {{
            renderInspector(defNode);
        }}
    }})();
    </script>
    """

    if "</body>" in html:
        html = html.replace("</body>", inspector_injection + "</body>")
    else:
        html = html + inspector_injection

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
    """Sprint 3 — Phase 4: Asset Inventory CSV. Prefers the persisted
    SQLite asset table (IP, MAC, Hostname, Vendor, OS, Device, Risk,
    Status, First Seen, Last Seen — exactly the sprint's column list)
    since that's the durable record; falls back to the live in-memory
    graph only if nothing has been persisted yet."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['IP', 'MAC', 'Hostname', 'Vendor', 'OS', 'Device Type', 'Risk',
                      'Criticality', 'Status', 'First Seen', 'Last Seen'])

    db_assets = monitor_db.get_live_assets()
    if db_assets:
        for a in db_assets:
            crit_label = CRITICALITY_LABELS.get(_safe_int(a.get('criticality')), a.get('criticality') or 'Unknown')
            writer.writerow([
                a.get('ip_address') or '', a.get('mac_address') or 'Unknown',
                a.get('hostname') or 'Unknown', a.get('vendor') or 'Unknown',
                a.get('operating_system') or 'unknown', a.get('device_type') or 'Unknown',
                a.get('current_risk') if a.get('current_risk') is not None else 'N/A',
                crit_label, a.get('status') or 'Unknown',
                (a.get('first_seen') or '')[:19], (a.get('last_seen') or '')[:19],
            ])
    else:
        for node, d in G.nodes(data=True):
            if d.get('node_type') == 'honeypot':
                continue
            writer.writerow([
                d.get('ip', ''), d.get('mac') or 'Unknown', d.get('hostname') or 'Unknown',
                d.get('mac_vendor') or 'Unknown', d.get('os', 'unknown'), d.get('device_type', 'Unknown'),
                d.get('risk_score', 0), d.get('criticality_label', 'Unknown'), 'ONLINE (this session)',
                '', '',
            ])
    return buf.getvalue()


def export_vulnerability_report_csv(G):
    """Sprint 3 — Phase 4: Vulnerability Report CSV. Leads with the
    sprint's exact column list (CVE, CVSS, Severity, Asset, Service,
    Version, Remediation, Status), keeping the extra evidence columns
    the app already tracked as trailing detail rather than dropping them.
    Status is always OPEN here — a patched CVE is removed from
    cve_findings the moment apply_defense_actions() runs, so anything
    still present in the live graph is, by definition, unresolved."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['CVE', 'CVSS', 'Severity', 'Asset', 'Service', 'Version', 'Remediation', 'Status',
                      'Description', 'Detection Confidence', 'Published', 'Modified', 'Source'])
    for node, d in G.nodes(data=True):
        fixes = d.get('fixes', [])
        for i, c in enumerate(d.get('cve_findings', [])):
            rec = fixes[i] if i < len(fixes) else (fixes[0] if fixes else 'See generic remediation guidance')
            writer.writerow([
                c.get('cve_id'), c.get('cvss'), c.get('severity'), d.get('display_name', node),
                c.get('service') or c.get('affected_product'), c.get('detected_version') or 'Unknown',
                rec, 'OPEN',
                c.get('summary'), c.get('detection_confidence'), c.get('published'), c.get('modified'),
                c.get('source'),
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


def build_executive_report_pdf(
    G, risk_score, blast_details, overall_risk, scan_history,
    defense_actions=None, applied_defenses=None,
    risk_before=None, blast_before=None, overall_before=None,
    risk_after=None, blast_after=None, overall_after=None,
    mitre_before=None, mitre_after=None, alerts=None,
):
    """Sprint 3 — Phase 4: professional Executive PDF report, built only
    from numbers the existing Sprint 2 risk pipeline already produced
    (no new/duplicate risk math). Returns raw PDF bytes.

    Deliberate scope note: the interactive exposure graph (pyvis/JS) has
    no headless renderer available in this environment, so the "Exposure
    Graph" section below is a structured reachability table rather than
    a rendered network diagram — the live interactive graph itself stays
    on the dashboard, untouched."""
    if not REPORTLAB_AVAILABLE:
        return None

    metrics = get_asset_metrics(G)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        title="ACDS Executive Security Report",
    )
    styles = getSampleStyleSheet()
    navy = colors.HexColor("#0d1f2d")
    accent = colors.HexColor("#0a3d5c")
    green = colors.HexColor("#0a7d4a")
    red = colors.HexColor("#b3213a")
    grey_line = colors.HexColor("#c9d6de")

    title_style = ParagraphStyle('ACDSTitle', parent=styles['Title'], textColor=navy, fontSize=20, spaceAfter=2)
    subtitle_style = ParagraphStyle('ACDSSubtitle', parent=styles['Normal'], textColor=colors.HexColor("#5a7a8c"),
                                     fontSize=9, spaceAfter=14)
    h2 = ParagraphStyle('ACDSH2', parent=styles['Heading2'], textColor=navy, fontSize=13,
                         spaceBefore=14, spaceAfter=6, borderColor=accent, borderWidth=0,
                         borderPadding=0)
    body = ParagraphStyle('ACDSBody', parent=styles['Normal'], fontSize=9.5, leading=13.5)
    small = ParagraphStyle('ACDSSmall', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#5a7a8c"))

    def severity_color(sev):
        return {"CRITICAL": red, "HIGH": colors.HexColor("#c9601c"),
                "MEDIUM": colors.HexColor("#b3891a"), "LOW": green}.get((sev or "").upper(), colors.grey)

    sev_hex = {"CRITICAL": "#b3213a", "HIGH": "#c9601c", "MEDIUM": "#b3891a", "LOW": "#0a7d4a"}

    elements = []

    # ---- Header / Company Security Posture -------------------------------
    elements.append(Paragraph("ACDS Executive Security Report", title_style))
    elements.append(Paragraph(
        f"Adaptive Cyber Defense System v3.0 &nbsp;|&nbsp; Generated "
        f"{datetime.now().strftime('%B %d, %Y %H:%M')} &nbsp;|&nbsp; "
        f"Passive scanning only — no exploitation performed", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.2, color=accent, spaceAfter=10))

    overall_score = overall_risk.get('overall_score') if overall_risk else None
    overall_status = overall_risk.get('status', 'N/A') if overall_risk else 'N/A'
    posture_sev = severity_from_score(overall_score) if overall_score is not None else "N/A"
    elements.append(Paragraph("Company Security Posture", h2))
    posture_text = (
        f"This assessment covers <b>{metrics['assets']}</b> discovered network assets. The current "
        f"<b>Overall ACDS Risk</b> is <b>{overall_score if overall_score is not None else 'N/A'}/100</b> "
        f"(<font color='{sev_hex.get(posture_sev, '#333333')}'>{posture_sev}</font>), "
        f"status: {overall_status}. {metrics['critical']} asset finding(s) rated CRITICAL and "
        f"{metrics['high']} rated HIGH require prioritized remediation."
    )
    elements.append(Paragraph(posture_text, body))
    elements.append(Spacer(1, 8))

    # ---- Overall Risk table ------------------------------------------------
    elements.append(Paragraph("Overall Risk", h2))
    risk_table_data = [["Metric", "Value"],
                        ["Overall ACDS Risk", f"{overall_score if overall_score is not None else 'N/A'}/100"],
                        ["Status", overall_status],
                        ["Network Blast Radius (spread)", f"{blast_details.get('spread', 'N/A')}%"],
                        ["Critical Assets Reachable", str(blast_details.get('critical_assets_reached', 'N/A'))],
                        ["Max Attack Depth (hops)", str(blast_details.get('max_lateral_hops', 'N/A'))],
                        ["Average Asset Risk", f"{metrics['average_risk']}/100"]]
    t = Table(risk_table_data, colWidths=[2.6 * inch, 3.4 * inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 9), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f6f8")]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 6))

    # ---- Asset Summary -------------------------------------------------
    elements.append(Paragraph("Asset Summary", h2))
    asset_summary_data = [["Total Assets", "Servers", "Other Devices", "Critical", "High", "Medium", "Low"],
                           [metrics['assets'], metrics['servers'], metrics['other_devices'],
                            metrics['critical'], metrics['high'], metrics['medium'], metrics['low']]]
    t = Table(asset_summary_data, colWidths=[0.95 * inch] * 7)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), accent), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 8.5), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 6))

    # ---- Critical Findings / Top CVEs --------------------------------
    elements.append(Paragraph("Critical Findings &amp; Top CVEs", h2))
    dedup = vuln_dedup.deduplicate_findings(G)
    top_cves = sorted(dedup, key=lambda x: x.get('cvss') or 0, reverse=True)[:12]
    if top_cves:
        rows = [["CVE", "CVSS", "Severity", "Affected Asset(s)"]]
        for f in top_cves:
            asset_names = ", ".join(a.get('display_name', '') for a in f.get('affected_assets', []))[:60]
            rows.append([f.get('cve_id', '—'), str(f.get('cvss', '—')), f.get('severity', '—'), asset_names])
        t = Table(rows, colWidths=[1.1 * inch, 0.6 * inch, 0.9 * inch, 3.3 * inch], repeatRows=1)
        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), navy), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]
        for i, f in enumerate(top_cves, start=1):
            style_cmds.append(('TEXTCOLOR', (2, i), (2, i), severity_color(f.get('severity'))))
        t.setStyle(TableStyle(style_cmds))
        elements.append(t)
    else:
        elements.append(Paragraph("No version-specific CVEs matched during this assessment.", small))
    elements.append(Spacer(1, 6))

    # ---- MITRE Attack Paths ---------------------------------------------
    elements.append(Paragraph("MITRE ATT&amp;CK Attack Paths (Simulated)", h2))
    elements.append(Paragraph(
        "SIMULATED — NO REAL ATTACK TRAFFIC. Techniques below reflect the last passive attack-path "
        "simulation run against the discovered topology.", small))
    if mitre_before:
        rows = [["MITRE Technique", "Description"]]
        for code, desc in list(mitre_before.items())[:15]:
            rows.append([code, (desc or '')[:80]])
        t = Table(rows, colWidths=[1.3 * inch, 4.6 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), navy), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
            ('TOPPADDING', (0, 0), (-1, -1), 3), ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(Spacer(1, 4))
        elements.append(t)
    else:
        elements.append(Paragraph("No attack simulation has been run yet.", small))
    elements.append(Spacer(1, 6))

    # ---- Exposure Graph (structured, since pyvis/JS has no headless render) --
    elements.append(Paragraph("Exposure Graph Summary", h2))
    real_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') != 'honeypot']
    top_reachable = sorted(
        [(n, d) for n, d in G.nodes(data=True) if d.get('node_type') != 'honeypot'],
        key=lambda x: x[1].get('criticality', 0), reverse=True)[:8]
    graph_rows = [["Asset", "IP", "Criticality", "Open Ports", "Reachable Neighbors"]]
    for n, d in top_reachable:
        graph_rows.append([
            d.get('display_name', n)[:22], d.get('ip', '—'),
            CRITICALITY_LABELS.get(d.get('criticality'), '—'),
            str(len(d.get('open_ports', []))), str(len(list(G.neighbors(n)))),
        ])
    elements.append(Paragraph(
        f"{len(real_nodes)} real assets, {G.number_of_edges()} exposure edges modeled. "
        f"Top nodes by business criticality shown below; the full interactive graph remains "
        f"available in the live dashboard.", small))
    t = Table(graph_rows, colWidths=[1.6 * inch, 1.1 * inch, 0.9 * inch, 0.9 * inch, 1.4 * inch], repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), accent), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 8), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
        ('TOPPADDING', (0, 0), (-1, -1), 3), ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(Spacer(1, 4))
    elements.append(t)
    elements.append(Spacer(1, 10))

    # ---- Alerts Summary -----------------------------------------------
    elements.append(Paragraph("Alerts Summary", h2))
    alerts = alerts or []
    if alerts:
        sev_counts = {}
        for a in alerts:
            sev_counts[a.get('severity', 'INFO')] = sev_counts.get(a.get('severity', 'INFO'), 0) + 1
        rows = [["Severity", "Count"]] + [[k, str(v)] for k, v in sorted(sev_counts.items(), key=lambda x: -x[1])]
        t = Table(rows, colWidths=[2 * inch, 1 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), navy), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 6))
        recent = alerts[:10]
        rows2 = [["Time", "Severity", "Message"]]
        for a in recent:
            msg = a.get('title') or a.get('description') or ''
            rows2.append([(a.get('timestamp') or '')[:19], a.get('severity', ''), msg[:70]])
        t2 = Table(rows2, colWidths=[1.3 * inch, 0.9 * inch, 3.8 * inch], repeatRows=1)
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), accent), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
            ('TOPPADDING', (0, 0), (-1, -1), 2), ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(t2)
    else:
        elements.append(Paragraph("No alerts recorded.", small))
    elements.append(Spacer(1, 6))

    # ---- Recommended Defenses ---------------------------------------
    elements.append(Paragraph("Recommended Defenses", h2))
    defense_actions = defense_actions or []
    if defense_actions:
        rows = [["Action", "Priority", "Cost", "Risk Reduction", "MITRE Tactic Mitigated"]]
        for a in defense_actions[:12]:
            rows.append([a.get('action', '')[:38], a.get('priority', 'MEDIUM'), str(a.get('cost', '')),
                         f"-{a.get('risk_reduction', 0)}", (a.get('mitre_tactic') or '')[:42]])
        t = Table(rows, colWidths=[1.9 * inch, 0.7 * inch, 0.5 * inch, 0.8 * inch, 2.2 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), navy), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
            ('TOPPADDING', (0, 0), (-1, -1), 3), ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("Run the Adaptive Defense Optimizer to generate recommendations.", small))
    elements.append(Spacer(1, 6))

    # ---- Before vs After Comparison ------------------------------------
    elements.append(Paragraph("Before vs After Verification", h2))
    if applied_defenses:
        rows = [["Metric", "Before", "After", "Change"]]

        def _delta(b, a):
            if b is None or a is None:
                return "—"
            d = round(a - b, 1)
            return f"{'+' if d > 0 else ''}{d}"

        ov_b = overall_before.get('overall_score') if overall_before else None
        ov_a = overall_after.get('overall_score') if overall_after else None
        rows.append(["Overall Risk", str(ov_b), str(ov_a), _delta(ov_b, ov_a)])
        rows.append(["Blast Radius", str(risk_before), str(risk_after), _delta(risk_before, risk_after)])
        cb = (blast_before or {}).get('critical_assets_reached')
        ca = (blast_after or {}).get('critical_assets_reached')
        rows.append(["Critical Assets Reachable", str(cb), str(ca), _delta(cb, ca)])
        db_ = (blast_before or {}).get('max_lateral_hops')
        da_ = (blast_after or {}).get('max_lateral_hops')
        rows.append(["Attack Depth (hops)", str(db_), str(da_), _delta(db_, da_)])
        rb = (blast_before or {}).get('systems_controlled')
        ra = (blast_after or {}).get('systems_controlled')
        rows.append(["Reachable Nodes", str(rb), str(ra), _delta(rb, ra)])
        t = Table(rows, colWidths=[2.1 * inch, 1.1 * inch, 1.1 * inch, 1.1 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), navy), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 9), ('GRID', (0, 0), (-1, -1), 0.5, grey_line),
            ('TOPPADDING', (0, 0), (-1, -1), 4), ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
        mitigated = set(mitre_before or {}) - set(mitre_after or {})
        if mitigated:
            elements.append(Spacer(1, 4))
            elements.append(Paragraph(f"Techniques neutralized by applied defenses: {', '.join(sorted(mitigated))}", small))
    else:
        elements.append(Paragraph(
            "No defenses have been applied yet in this session — apply recommendations from the "
            "Adaptive Defense Optimizer to populate this comparison.", small))
    elements.append(Spacer(1, 8))

    # ---- Executive Conclusion -------------------------------------------
    elements.append(Paragraph("Executive Conclusion", h2))
    if applied_defenses and overall_before and overall_after:
        ov_b = overall_before.get('overall_score')
        ov_a = overall_after.get('overall_score')
        conclusion = (
            f"Applying the {len(applied_defenses)} selected defense action(s) reduced Overall ACDS Risk "
            f"from {ov_b} to {ov_a} ({_delta(ov_b, ov_a)} points). "
            f"Continued monitoring and remediation of the remaining {metrics['critical']} critical and "
            f"{metrics['high']} high-severity findings is recommended to sustain this posture."
        )
    else:
        conclusion = (
            f"The network's current Overall ACDS Risk is {overall_score if overall_score is not None else 'N/A'}/100 "
            f"({posture_sev}). Reviewing and applying the Adaptive Defense Optimizer's recommended controls "
            f"is the fastest path to a measurable risk reduction, verifiable on the Before vs After page."
        )
    elements.append(Paragraph(conclusion, body))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=0.75, color=grey_line))
    elements.append(Paragraph(
        "Generated by ACDS v3.0 — Adaptive Cyber Defense System. Passive scanning only. "
        "All attack simulations are non-destructive and generate no real network traffic.", small))

    doc.build(elements)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ─────────────────────────────────────────────────────────────────

# Priority 27 / Sprint 1: initialize the SQLite persistence layers FIRST,
# since the `defaults` dict below seeds a couple of values (budget,
# monitor_interval) from persisted Settings (Sprint 3 — Phase 8) and
# needs the `settings` table to already exist.
database.init_db()
monitor_db.init_db()
_persisted_settings = monitor_db.get_all_settings()

defaults = {
    "network_mode": "Real Network Scan", "simulation_done": False, "timeline": [],
    "compromised": set(), "risk_score": 0.0, "blast_details": {},
    "honeypot_triggered": False, "defense_actions": [], "selected_defenses": [],
    "applied_defenses": [], "ids_deployed": False, "segmentation_applied": False,
    "attack_log": [], "attack_stats": {}, "current_anim_node": None,
    "last_scan_devices": None, "scan_started_at": None, "scan_completed_at": None,
    "scan_error": None, "scan_timeline": [], "scan_history": [], "scan_counter": 0,
    "risk_before_defense": None, "blast_before_defense": {},
    "post_defense_stats": None, "overall_acds_risk": None,
    "budget": _persisted_settings["default_budget"],
    # Sprint 3 — Phase 2: Before vs After Verification page needs the
    # OVERALL ACDS Risk snapshot too, not just the blast-radius risk_score.
    "overall_acds_risk_before": None, "mitre_before_defense": {},
    "mitre_after_defense": {},
    "change_summary": None, "adaptive_feedback": None,
    # Sprint 1 — persistent monitoring (core/database.py)
    "monitoring_enabled": False, "monitor_interval": _persisted_settings["monitoring_interval"],
    "monitor_base_ip": None, "monitor_scan_limit": 100,
    "monitor_last_run": None, "monitor_last_error": None,
    "monitor_run_count": 0, "monitor_last_changes": [],
    # Sprint 3 — Phase 7: re-entrancy guard shared by the manual scan
    # button and the background monitoring pass.
    "scan_in_progress": False,
    "monitor_last_snapshot_id": None,
    # Sprint 2 — Dynamic Risk Intelligence (Phases 1-10)
    "last_entry_node": None, "blast_radius_last_computed": None,
    "alerts": [], "cve_timeline": [],
    "prev_asset_snapshot": {}, "prev_graph_edges": set(),
    "new_exposure_edges": set(), "removed_exposure_edges": set(),
    "risk_history_last_run": None,
    # Dynamic Network Environment Context
    "network_env": None,
    # Level 2 — Real-Time Defensive Validation Engine State
    "live_validation_results": {},
    "last_validation_time": None,
    "validation_changes": [],
    "validation_target_selection": "All Discovered Authorized Assets",
    "continuous_val_active": False,
    "continuous_val_interval": "30s",
    # ACDS Attack & Defense Storyline Demonstration Workflow
    "demo_target_ip": "",
    "demo_controller_ip": "",
    "demo_router_ip": "",
    "demo_stage": 1,
    "demo_max_stage_reached": 1,
    "demo_data": {},
    "demo_stage_status": {i: "Not Started" for i in range(1, 13)},
    "demo_running": False,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

if not st.session_state.get("network_env"):
    st.session_state["network_env"] = detect_network_environment()

_net_env = st.session_state["network_env"]
if not st.session_state.get("demo_controller_ip"):
    st.session_state["demo_controller_ip"] = _net_env.get("controller_ip") or "127.0.0.1"
if not st.session_state.get("demo_router_ip"):
    st.session_state["demo_router_ip"] = _net_env.get("gateway_ip") or "192.168.0.1"

if "G" not in st.session_state:
    st.session_state.G = build_network() if st.session_state.network_mode == "Simulated Lab" else nx.DiGraph()

# Sprint 3 — Phase 8: apply persisted settings to the runtime knobs
# (scan timeouts, NVD cache TTL, risk thresholds, alert severity floor).
# Called once here at startup; the Settings panel calls it again
# immediately after a save so changes take effect without a restart.
apply_runtime_settings(_persisted_settings)


def _device_record_to_monitor_dict(rec):
    """Adapt a _parse_device_record()-shaped dict (already used by
    build_dynamic_graph) into the flat shape core.database.record_monitoring_scan
    expects, resolving port -> service name via the existing PORT_SERVICE_MAP
    so Sprint 1 never duplicates that lookup table."""
    version_map = rec.get('version_map') or {}
    banner_map = rec.get('banner_map') or {}
    ports = []
    for port in rec.get('open_ports') or []:
        service = PORT_SERVICE_MAP.get(port, 'unknown')
        ports.append({
            'port': port, 'protocol': 'tcp', 'service': service,
            'version': version_map.get(service), 'banner': banner_map.get(service),
        })
    return {
        'ip': rec.get('ip'), 'mac': rec.get('mac'), 'hostname': rec.get('hostname'),
        'vendor': rec.get('mac_vendor'), 'os': rec.get('os'), 'device_type': rec.get('device_type'),
        'criticality': None, 'current_risk': None,
        'ports': ports,
    }


def run_monitoring_iteration():
    """Sprint 1 — Phase 5 / Sprint 2 — Phase 10: one passive monitoring pass:
    Discovery -> Service Scan -> Store Snapshot -> Change Detection, then
    (Sprint 2) Exposure Graph Update -> Asset Risk Update -> Blast Radius
    Update -> Overall Risk Update -> Risk History -> Alert Generation —
    automatically, with no manual "recompute" button.

    Deliberately reuses scan_network() (the exact same passive
    ping/ARP/port-scan/banner-grab pipeline as the manual "SCAN NETWORK"
    button) instead of duplicating discovery logic.

    Sprint 3 — Phase 7: guarded against re-entrancy (skips this pass if a
    manual scan or a previous monitoring pass is still in flight) and
    validates its own scan scope every run, since monitor_base_ip is
    saved config that could in principle go stale/invalid between runs."""
    if st.session_state.get("scan_in_progress"):
        acds_log.info("Monitoring pass skipped — a scan is already in progress")
        return
    base_ip = st.session_state.get("monitor_base_ip") or None
    scan_limit = st.session_state.get("monitor_scan_limit", 100)

    if base_ip is not None:
        valid, reason = validate_scan_scope(base_ip, scan_limit)
        if not valid:
            st.session_state.monitor_last_error = f"Invalid monitoring scan scope: {reason}"
            acds_log.warning("Monitoring pass aborted — invalid scope: %s", reason)
            return

    st.session_state.scan_in_progress = True
    t0 = time.time()
    try:
        devices, _timeline = scan_network(base_ip=base_ip, limit=scan_limit)
    except Exception as exc:
        st.session_state.monitor_last_error = f"{type(exc).__name__}: {exc}"
        acds_log.error("Monitoring scan_network() failed: %s: %s", type(exc).__name__, exc)
        return
    finally:
        st.session_state.scan_in_progress = False

    duration = round(time.time() - t0, 2)
    parsed = [_parse_device_record(d) for d in devices]
    monitor_devices = [_device_record_to_monitor_dict(rec) for rec in parsed]
    subnet = base_ip or (get_local_ip().rsplit('.', 1)[0] + '.')

    try:
        changes, snapshot_id = monitor_db.record_monitoring_scan(
            monitor_devices, subnet=subnet, duration=duration)
    except Exception as exc:
        st.session_state.monitor_last_error = f"{type(exc).__name__}: {exc}"
        return

    st.session_state.monitor_last_error = None
    st.session_state.monitor_last_run = datetime.now(timezone.utc)
    st.session_state.monitor_run_count += 1
    st.session_state.monitor_last_changes = changes
    st.session_state.monitor_last_snapshot_id = snapshot_id

    # Sprint 2 — Phase 10: every monitoring pass that found live devices
    # rebuilds the exposure graph (Phase 2 network exposure + Priority 6
    # asset risk are both recomputed inside build_dynamic_graph itself),
    # then runs the rest of the automatic pipeline. A pass with zero
    # devices (e.g. transient network blip) is skipped rather than wiping
    # the live graph down to nothing.
    if devices:
        st.session_state.G = build_dynamic_graph(devices)
        st.session_state.last_scan_devices = devices
        run_dynamic_risk_pipeline("MONITORING")


def _asset_risk_snapshot_from_graph(G):
    """Sprint 2: flatten the live graph into an IP-keyed snapshot for the
    alert engine (core/alert_engine.py) and risk history persistence.
    Skips honeypot decoy nodes — same convention as
    core.change_detector.graph_to_asset_snapshot()."""
    snapshot = {}
    for node, data in G.nodes(data=True):
        if data.get("node_type") == "honeypot":
            continue
        ip = data.get("ip")
        if not ip:
            continue
        cve_findings = data.get("cve_findings") or []
        cve_ids = sorted({c.get("cve_id") for c in cve_findings if c.get("cve_id")})
        cve_cvss = {c.get("cve_id"): c.get("cvss") for c in cve_findings if c.get("cve_id")}
        snapshot[ip] = {
            "hostname": data.get("hostname"),
            "risk_score": data.get("risk_score"),
            "risk_severity": data.get("risk_severity"),
            "criticality": data.get("criticality"),
            "cve_ids": cve_ids,
            "cve_cvss": cve_cvss,
            "exposed": bool(G.in_degree(node) > 0 or data.get("open_ports")),
        }
    return snapshot


def _graph_reachability_edges(G):
    """Sprint 2 — Phase 5: IP-keyed set of modeled POTENTIAL REACHABILITY
    edges, used to detect newly-created/removed exposure paths."""
    edges = set()
    for src, dst in G.edges():
        sip, dip = G.nodes[src].get("ip"), G.nodes[dst].get("ip")
        if sip and dip:
            edges.add((sip, dip))
    return edges


def recompute_blast_radius_for_current_topology():
    """Sprint 2 — Phase 6: automatically re-run the (still simulated,
    still non-exploitative) blast-radius simulation against the CURRENT
    graph topology, reusing the last entry point / deployed defenses this
    session ever used. If no simulation baseline exists yet (nobody has
    picked an entry node this session), this is a no-op — Overall ACDS
    Risk stays PARTIAL, same as before Sprint 2, rather than inventing an
    entry point no one chose."""
    G = st.session_state.G
    entry = st.session_state.get("last_entry_node")
    if not entry or entry not in G.nodes:
        return

    for node in G.nodes:
        G.nodes[node]["compromised"] = False

    timeline, compromised, honeypot_triggered, attack_stats = simulate_attack(
        G, entry, seed=random.randint(1, 9999),
        ids_deployed=st.session_state.ids_deployed,
        segmentation_applied=st.session_state.segmentation_applied,
    )
    risk_score, blast_details = calculate_risk(G, compromised, timeline, honeypot_triggered, attack_stats)

    st.session_state.timeline = timeline
    st.session_state.compromised = compromised
    st.session_state.honeypot_triggered = honeypot_triggered
    st.session_state.risk_score = risk_score
    st.session_state.blast_details = blast_details
    st.session_state.attack_stats = attack_stats
    st.session_state.simulation_done = True
    st.session_state.blast_radius_last_computed = datetime.now(timezone.utc)
    st.session_state.defense_actions = get_defense_actions(G, compromised, risk_score)
    selected, _reduction, _remaining = greedy_defense_selection(
        st.session_state.defense_actions, st.session_state.budget)
    st.session_state.selected_defenses = selected
    st.session_state.attack_log = generate_attack_log(timeline, honeypot_triggered)

    if honeypot_triggered:
        honeypot_engine.record_trigger(
            source_node=entry, decoy_node="Honeypot (decoy)",
            event_type="simulated_probe",
            details="Simulated attacker reached the decoy node during an automatic blast-radius recompute.",
            risk_before=risk_score - 15 if risk_score is not None else None,
            risk_after=risk_score,
        )
    st.session_state.adaptive_feedback = honeypot_engine.apply_adaptive_feedback(risk_score)


def persist_dynamic_risk_pipeline(trigger):
    """Sprint 2 — Phase 10: the last three stages of the automatic
    recalculation pipeline — Risk History and Alert Generation — run
    against whatever is CURRENTLY in st.session_state.G / risk_score /
    overall_acds_risk. Diffs against the previous pass (stored in
    st.session_state) to produce RISK_INCREASE/DECREASE, NEW_CVE,
    CRITICAL_ASSET_EXPOSED, and NEW_EXPOSURE_PATH alerts, plus the CVE
    lifecycle timeline (Phase 9). Safe to call with no prior baseline —
    the first pass just seeds the snapshot with no diff-based alerts.
    """
    G = st.session_state.G
    now_iso = datetime.now(timezone.utc).isoformat()

    after_snapshot = _asset_risk_snapshot_from_graph(G)
    after_edges = _graph_reachability_edges(G)
    before_snapshot = st.session_state.get("prev_asset_snapshot") or {}
    before_edges = st.session_state.get("prev_graph_edges") or set()

    alerts = alert_engine.generate_change_alerts(
        before_snapshot, after_snapshot, before_edges, after_edges,
        st.session_state.get("honeypot_triggered", False), now_iso,
    )
    # Sprint 3 — Phase 8: Alert Severity Threshold setting — alerts below
    # the configured floor are dropped BEFORE they're persisted, so a
    # noisy LOW/INFO-heavy network doesn't drown out what the user
    # actually asked to be notified about.
    min_rank = _SEVERITY_RANK.get(ALERT_SEVERITY_THRESHOLD, 0)
    alerts = [a for a in alerts if _SEVERITY_RANK.get(a.get("severity", "INFO"), 0) >= min_rank]
    if alerts:
        monitor_db.create_alerts(alerts)
        st.session_state.alerts = (alerts + st.session_state.get("alerts", []))[:200]

    cve_events = alert_engine.build_cve_lifecycle_events(before_snapshot, after_snapshot, now_iso)
    if cve_events:
        monitor_db.record_cve_events(cve_events)
    st.session_state.cve_timeline = (list(reversed(cve_events)) + st.session_state.get("cve_timeline", []))[:100]

    overall = st.session_state.get("overall_acds_risk") or {}
    blast_score = st.session_state.risk_score if st.session_state.get("simulation_done") else None
    asset_rows = [{"asset_ip": ip, "asset_risk": d.get("risk_score")} for ip, d in after_snapshot.items()]
    monitor_db.record_risk_history(asset_rows, overall.get("overall_score"), blast_score, trigger)
    # Sprint 3 — Phase 3: keep the `assets` table's current_risk/criticality
    # in sync so the Executive Dashboard works after a manual scan or a
    # simulation too, not only after background monitoring passes.
    monitor_db.update_asset_current_state(after_snapshot)

    st.session_state.new_exposure_edges = after_edges - before_edges
    st.session_state.removed_exposure_edges = before_edges - after_edges
    st.session_state.prev_asset_snapshot = after_snapshot
    st.session_state.prev_graph_edges = after_edges
    st.session_state.risk_history_last_run = now_iso


def run_dynamic_risk_pipeline(trigger, recompute_blast=True):
    """Sprint 2 — Phase 10: AUTOMATIC RECALCULATION PIPELINE.

    Change Detection (already done by the caller) -> Exposure Graph Update
    (already done by the caller rebuilding st.session_state.G, which itself
    runs Phase 2 network-exposure + Priority 6 asset-risk recompute) ->
    Blast Radius Update -> Overall Risk Update -> Risk History -> Alert
    Generation. No manual "recompute" button anywhere calls this directly
    for its own sake — it is always triggered BY a topology-changing event
    (a scan, a monitoring pass, or a simulation run) per the Sprint 2 spec.
    """
    if recompute_blast:
        recompute_blast_radius_for_current_topology()

    st.session_state.overall_acds_risk = calculate_overall_acds_risk(
        st.session_state.G,
        st.session_state.risk_score if st.session_state.get("simulation_done") else None,
    )
    persist_dynamic_risk_pipeline(trigger)


def record_scan_history(G, scan_type):
    """Priority 21: in-session scan history (fast UI list) PLUS Priority 13/27:
    persist the scan + a per-asset snapshot to SQLite, and diff it against the
    last persisted snapshot so Change Detection survives app restarts instead
    of only living in st.session_state."""
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

    # Only real, non-empty scans of actual discovered assets are meaningful
    # to persist and diff (skip empty "Simulated Lab" graphs).
    current_assets = change_detector.graph_to_asset_snapshot(G)
    if current_assets:
        prev_scan_id = database.get_latest_scan_id()
        previous_assets = database.get_snapshot(prev_scan_id)
        st.session_state.change_summary = change_detector.diff_scans(previous_assets, current_assets)
        database.save_scan(scan_type, metrics, current_assets)


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
        net_env = st.session_state.get("network_env") or detect_network_environment()
        st.session_state["network_env"] = net_env

        st.markdown(f"""
        <div style='background:rgba(0,212,255,0.06);border:1px solid #00d4ff;padding:8px 10px;border-radius:4px;margin:8px 0;font-family:Share Tech Mono;font-size:0.65rem;color:#e0f4ff;line-height:1.6'>
            <div style='color:#00d4ff;font-weight:bold;margin-bottom:2px'>📡 ACTIVE INTERFACE</div>
            <div><b>Adapter:</b> {net_env.get('adapter_name', 'Default')}</div>
            <div><b>Local IP:</b> <code>{net_env.get('controller_ip')}</code></div>
            <div><b>Subnet:</b> <code>{net_env.get('subnet_cidr')}</code></div>
            <div><b>Gateway:</b> <code>{net_env.get('gateway_ip')}</code></div>
        </div>
        """, unsafe_allow_html=True)

        discovery_mode = st.radio(
            "Discovery Mode",
            ["Automatic Subnet Discovery", "Controlled Target / Range"],
            index=0,
            help="Choose between scanning the detected subnet or targeting specific lab IPs/ranges."
        )

        target_spec_ips = None
        base_ip = None
        scan_limit = 254

        if discovery_mode == "Automatic Subnet Discovery":
            base_ip = net_env.get('base_ip_prefix') or get_local_ip()
            scan_limit = st.slider("Host Scan Range (1 to ...)", 10, 254, 100, 10,
                                   help=f"Scans {base_ip}1 up to {base_ip}{scan_limit}")
        else:
            custom_target = st.text_input(
                "Target IP / Range / CIDR",
                value=net_env.get('subnet_cidr') or "192.168.1.0/24",
                help="Enter single IP (e.g. 192.168.0.101), range (e.g. 1-30), CIDR (e.g. 192.168.0.0/24), or comma-separated IPs"
            )
            target_spec_ips = parse_target_ips(custom_target, net_env.get('base_ip_prefix'))
            if target_spec_ips:
                st.caption(f"✓ {len(target_spec_ips)} target IP(s) queued for scan")
            else:
                st.caption("Enter a valid IPv4 address, range, or CIDR")

        if st.button("📡  SCAN NETWORK", use_container_width=True, disabled=st.session_state.get("scan_in_progress", False)):
            valid, reason = (True, None) if target_spec_ips or base_ip is None else validate_scan_scope(base_ip, scan_limit)
            if not valid:
                st.error(f"Scan not started — invalid scan scope: {reason}")
            elif st.session_state.get("scan_in_progress"):
                st.warning("A scan is already in progress — please wait for it to finish.")
            else:
                st.session_state.scan_in_progress = True
                try:
                    progress_bar = st.progress(0, text="Starting scan...")

                    def _progress(done, total):
                        if total > 0:
                            progress_bar.progress(min(done / total, 1.0), text=f"Profiling host {done}/{total}...")

                    st.session_state.scan_started_at = datetime.now(timezone.utc)
                    st.session_state.scan_error = None
                    try:
                        with st.spinner("Pinging subnet and discovering hosts..."):
                            devices, scan_timeline = scan_network(
                                base_ip=base_ip if not target_spec_ips else None,
                                limit=scan_limit,
                                target_ips=target_spec_ips,
                                progress_cb=_progress
                            )
                    except Exception as exc:
                        devices, scan_timeline = [], []
                        st.session_state.scan_error = f"Scan failed safely: {type(exc).__name__}: {exc}"
                        acds_log.error("Manual scan failed: %s: %s", type(exc).__name__, exc)
                    finally:
                        st.session_state.scan_completed_at = datetime.now(timezone.utc)
                        progress_bar.empty()

                    if st.session_state.scan_error:
                        st.error(st.session_state.scan_error)
                        st.toast("❌ Scan failed — see details above", icon="❌")
                    elif not devices:
                        st.warning("No active devices found. Check your network prefix or range.")
                        st.toast("No devices found", icon="⚠️")
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
                        # Sprint 2 — Phase 10: a manual scan is itself a topology-changing
                        # event (new/removed assets, port changes), so it drives the same
                        # automatic pipeline as a background monitoring pass.
                        run_dynamic_risk_pipeline("MANUAL_SCAN")
                        st.success(f"Found {len(devices)} device(s). Real banners + CVE lookups + ACDS risk model applied.")
                        st.toast(f"📡 Scan complete — {len(devices)} device(s) found", icon="📡")
                finally:
                    st.session_state.scan_in_progress = False
                st.rerun()
        # ─────────────────────────────────────────────────────
        # SPRINT 1 — PHASE 5: PERSISTENT / BACKGROUND MONITORING
        # ─────────────────────────────────────────────────────
        st.markdown('<div class="section-header">🛰 PERSISTENT MONITORING</div>', unsafe_allow_html=True)
        st.session_state.monitor_base_ip = base_ip
        st.session_state.monitor_scan_limit = scan_limit

        interval_choice = st.selectbox(
            "Monitoring interval", ["30s", "1m", "5m"],
            index=["30s", "1m", "5m"].index(st.session_state.monitor_interval),
            help="How often ACDS re-runs discovery + service scan in the background while this tab is open.",
        )
        st.session_state.monitor_interval = interval_choice

        mon_col1, mon_col2 = st.columns(2)
        with mon_col1:
            if st.button("▶ START MONITORING", use_container_width=True,
                         disabled=st.session_state.monitoring_enabled):
                st.session_state.monitoring_enabled = True
                st.rerun()
        with mon_col2:
            if st.button("■ STOP MONITORING", use_container_width=True,
                         disabled=not st.session_state.monitoring_enabled):
                st.session_state.monitoring_enabled = False
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
        )

    show_honeypot = st.checkbox("Show Honeypot Node (simulation view)", value=True)
    animation_speed = st.slider("Animation Speed (sec/step)", 0.3, 2.0, 0.6, 0.1)

# ─────────────────────────────────────────────────────────────────
# MAIN LAYOUT
# ─────────────────────────────────────────────────────────────────

st.markdown("""
<div class="cyber-header">
    <div class="cyber-title">🛡 ADAPTIVE CYBER DEFENSE SYSTEM</div>
    <div class="cyber-subtitle">// NETWORK EXPOSURE & ATTACK PATH MODEL • EXPLAINABLE RISK • SIMULATION-BASED DEFENSE OPTIMIZATION //</div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────
# SPRINT 3 — PHASE 3: EXECUTIVE CYBER DASHBOARD (top KPI row)
# ─────────────────────────────────────────────────────────────────
asset_metrics = get_asset_metrics(st.session_state.G)
_db_asset_count = monitor_db.get_asset_count()
_db_live_assets = monitor_db.get_live_assets()

_total_assets = _db_asset_count["total"] or asset_metrics["assets"]
_critical_assets = (sum(1 for a in _db_live_assets if (_safe_int(a.get("criticality")) or 0) >= 4)
                     if _db_live_assets else
                     sum(1 for _, d in st.session_state.G.nodes(data=True) if (d.get("criticality") or 0) >= 4))
_active_vulns = len(vuln_dedup.deduplicate_findings(st.session_state.G))
_overall_obj = st.session_state.get("overall_acds_risk") or calculate_overall_acds_risk(st.session_state.G, st.session_state.risk_score)
_overall_display = f"{_overall_obj['overall_score']}/100" if _overall_obj and _overall_obj.get("overall_score") is not None else "—"
_active_alerts = len(monitor_db.get_alerts(limit=500))

# Pre-calculate overall ACDS risk
overall = _overall_obj

# Helper definitions for UI components
_CHANGE_ICONS = {
    "NEW_ASSET": "🟢", "REMOVED_ASSET": "⚫", "NEW_PORT": "🟠",
    "CLOSED_PORT": "🔵", "SERVICE_CHANGED": "🟡", "VERSION_CHANGED": "🟣",
}

def _render_change_entry(c):
    icon = _CHANGE_ICONS.get(c["type"], "⚪")
    if c["type"] == "NEW_ASSET":
        body = f"New device detected<br><b>{c['asset']}</b>" + (f" &middot; {c['hostname']}" if c.get('hostname') else "")
        label = "New device detected"
    elif c["type"] == "REMOVED_ASSET":
        body = f"Device offline<br><b>{c['asset']}</b>"
        label = "Device offline"
    elif c["type"] == "NEW_PORT":
        body = f"New port opened<br><b>{c['asset']}</b><br>{c['port']} / {c.get('service') or 'unknown'}"
        label = "New port opened"
    elif c["type"] == "CLOSED_PORT":
        body = f"Port closed<br><b>{c['asset']}</b><br>{c['port']} / {c.get('service') or 'unknown'}"
        label = "Port closed"
    elif c["type"] == "SERVICE_CHANGED":
        body = f"Service changed<br><b>{c['asset']}</b><br>port {c['port']}: {c.get('before_service')} → {c.get('after_service')}"
        label = "Service changed"
    else:  # VERSION_CHANGED
        body = f"Version changed<br><b>{c['asset']}</b><br>{c.get('service')} {c.get('before_version')} → {c.get('after_version')}"
        label = "Version changed"
    sev = c.get("severity", "LOW")
    sev_color = {"HIGH": "#ff3355", "MEDIUM": "#ff8c00", "LOW": "#3d6a8a"}.get(sev, "#3d6a8a")
    st.markdown(f"""
    <div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;
         padding:8px 10px;margin:4px 0;background:#0a1520;border-left:3px solid {sev_color}">
        <span style="font-size:0.9rem">{icon}</span>
        <span style="color:#e0f4ff;margin-left:4px">{label}</span>
        <span style="float:right;color:{sev_color};font-size:0.6rem">{sev}</span>
        <div style="margin-top:4px;color:#7ab8d4">{body}</div>
    </div>
    """, unsafe_allow_html=True)

def _render_monitoring_panel():
    if st.session_state.monitoring_enabled:
        run_monitoring_iteration()

    counts = monitor_db.get_asset_count()
    last_run = st.session_state.monitor_last_run
    last_run_txt = last_run.strftime("%Y-%m-%d %H:%M:%S UTC") if last_run else "never"
    st.markdown(
        f'<div style="font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;margin-bottom:6px">'
        f'Tracked assets: <span style="color:#00d4ff">{counts["total"]}</span> total, '
        f'<span style="color:#00ff88">{counts["online"]}</span> online &middot; '
        f'last monitoring pass: <span style="color:#7ab8d4">{last_run_txt}</span> &middot; '
        f'passes run this session: {st.session_state.monitor_run_count}</div>',
        unsafe_allow_html=True,
    )

    live_col, changes_col = st.columns([3, 2], gap="medium")

    with live_col:
        st.markdown('<div class="section-header">📡 LIVE ASSET INVENTORY</div>', unsafe_allow_html=True)
        live_assets = monitor_db.get_live_assets()
        if not live_assets:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No assets tracked yet — run SCAN NETWORK or START MONITORING.</div>',
                unsafe_allow_html=True)
        else:
            rows_html = []
            for a in live_assets:
                dot = "🟢" if a["status"] == "ONLINE" else "⚫"
                rows_html.append(
                    f"<tr style='border-bottom:1px solid #1a3a5c'>"
                    f"<td style='padding:4px 6px'>{dot} {a['status']}</td>"
                    f"<td style='padding:4px 6px'>{a['ip_address'] or '—'}</td>"
                    f"<td style='padding:4px 6px'>{a['hostname'] or '—'}</td>"
                    f"<td style='padding:4px 6px'>{a['device_type'] or '—'}</td>"
                    f"<td style='padding:4px 6px'>{a['operating_system'] or '—'}</td>"
                    f"<td style='padding:4px 6px'>{a['vendor'] or '—'}</td>"
                    f"<td style='padding:4px 6px'>{(a['first_seen'] or '')[:19]}</td>"
                    f"<td style='padding:4px 6px'>{(a['last_seen'] or '')[:19]}</td>"
                    f"</tr>"
                )
            st.markdown(f"""
            <div style="max-height:340px;overflow-y:auto">
            <table style="width:100%;border-collapse:collapse;font-family:Share Tech Mono;
                   font-size:0.62rem;color:#7ab8d4">
            <thead><tr style="color:#00d4ff;border-bottom:1px solid #00d4ff">
            <th style='text-align:left;padding:4px 6px'>Status</th>
            <th style='text-align:left;padding:4px 6px'>IP</th>
            <th style='text-align:left;padding:4px 6px'>Hostname</th>
            <th style='text-align:left;padding:4px 6px'>Device</th>
            <th style='text-align:left;padding:4px 6px'>OS</th>
            <th style='text-align:left;padding:4px 6px'>Vendor</th>
            <th style='text-align:left;padding:4px 6px'>First Seen</th>
            <th style='text-align:left;padding:4px 6px'>Last Seen</th>
            </tr></thead>
            <tbody>{''.join(rows_html)}</tbody>
            </table>
            </div>
            """, unsafe_allow_html=True)

    with changes_col:
        st.markdown('<div class="section-header">🔔 NETWORK CHANGES</div>', unsafe_allow_html=True)
        changes = st.session_state.monitor_last_changes
        if not changes:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No changes detected since the last monitoring pass.</div>',
                unsafe_allow_html=True)
        else:
            for c in changes[:25]:
                _render_change_entry(c)

_TIMELINE_ICONS = {
    "NEW_ASSET": "🟢", "REMOVED_ASSET": "⚫", "NEW_PORT": "🟠", "CLOSED_PORT": "🔵",
    "SERVICE_CHANGED": "🟡", "VERSION_CHANGED": "🟣",
    "RISK_INCREASE": "🔴", "RISK_DECREASE": "🟢",
}
_TIMELINE_LABELS = {
    "NEW_ASSET": "New Asset", "REMOVED_ASSET": "Device Offline",
    "NEW_PORT": "Port Opened", "CLOSED_PORT": "Port Closed",
    "SERVICE_CHANGED": "Service Changed", "VERSION_CHANGED": "Version Changed",
    "RISK_INCREASE": "Overall Risk Increased", "RISK_DECREASE": "Risk Reduced",
}

def render_recent_changes_timeline():
    st.markdown('<div class="section-header">📜 RECENT CHANGES</div>', unsafe_allow_html=True)
    rows = monitor_db.get_recent_timeline(limit=30)
    if not rows:
        st.markdown(
            '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
            'No changes recorded yet. Enable monitoring or run a scan to start building history.</div>',
            unsafe_allow_html=True)
        return

    entries_html = []
    for r in rows:
        ts = (r.get("timestamp") or "")
        time_label = ts[11:16] if len(ts) >= 16 else ts
        icon = _TIMELINE_ICONS.get(r["kind"], "⚪")
        label = _TIMELINE_LABELS.get(r["kind"], r["kind"])
        asset = html_lib.escape(str(r.get("asset") or ""))
        detail = html_lib.escape(str(r.get("detail") or ""))
        entries_html.append(f"""
        <div style='padding:8px 4px;border-bottom:1px solid #142a3a'>
            <span style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.68rem'>{time_label}</span>
            <span style='margin-left:10px;font-size:0.85rem'>{icon}</span>
            <span style='color:#e0f4ff;font-family:Share Tech Mono;font-size:0.72rem;margin-left:4px'>{label}</span>
            <div style='color:#7ab8d4;font-family:Share Tech Mono;font-size:0.68rem;margin:2px 0 0 62px'>
                {asset}{' — ' + detail if detail and detail != label else ''}
            </div>
        </div>""")

    st.markdown(
        f"<div style='max-height:340px;overflow-y:auto;background:#0a1520;border:1px solid #1a3a5c;padding:4px 10px'>"
        f"{''.join(entries_html)}</div>", unsafe_allow_html=True)

_ALERT_SEVERITY_COLOR = {
    "CRITICAL": "#ff3355", "HIGH": "#ff8c00", "MEDIUM": "#ffd700",
    "LOW": "#3d6a8a", "INFO": "#00d4ff",
}
_ALERT_TYPE_ICON = {
    "NEW_CVE": "🧬", "RISK_INCREASE": "📈", "RISK_DECREASE": "📉",
    "CRITICAL_ASSET_EXPOSED": "🚨", "NEW_EXPOSURE_PATH": "🛣", "HONEYPOT_PATH": "🍯",
}

def _render_alert_card(a):
    sev = a.get("severity", "INFO")
    color = _ALERT_SEVERITY_COLOR.get(sev, "#3d6a8a")
    icon = _ALERT_TYPE_ICON.get(a.get("alert_type"), "🔔")
    delta_html = ""
    if a.get("old_value") and a.get("new_value"):
        delta_html = (f"<div style='color:#e0f4ff;font-family:Orbitron,monospace;font-size:0.8rem;margin-top:4px'>"
                      f"{html_lib.escape(str(a['old_value']))} → {html_lib.escape(str(a['new_value']))}</div>")
    ts = (a.get("timestamp") or "")[:19].replace("T", " ")
    st.markdown(f"""
    <div style='background:#0d1f2d;border:1px solid {color};border-left:4px solid {color};
         padding:10px 14px;margin:6px 0;font-family:Share Tech Mono;font-size:0.7rem;color:#7ab8d4'>
        <div style='display:flex;justify-content:space-between;align-items:center'>
            <span style='color:{color};font-weight:bold'>{icon} {sev} — {a.get("title","")}</span>
            <span style='color:#3d6a8a;font-size:0.6rem'>{ts}</span>
        </div>
        <div style='color:#e0f4ff;margin-top:2px'>Asset: {html_lib.escape(str(a.get("asset") or "-"))}</div>
        <div style='margin-top:2px'>{html_lib.escape(str(a.get("description") or ""))}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# ⚔️ DYNAMIC DECISION-BASED PROPAGATION TAB RENDERER
# ─────────────────────────────────────────────────────────────────

def render_decision_propagation_tab():
    st.markdown('<div class="section-header">⚔️ ACDS LEVEL 2: REAL-TIME DEFENSIVE VALIDATION &amp; PROPAGATION SIMULATOR</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style='background:rgba(0,212,255,0.05);border:1px solid #00d4ff;padding:12px 18px;border-radius:4px;
         font-family:Share Tech Mono;font-size:0.75rem;color:#7ab8d4;line-height:1.8;margin-bottom:16px'>
        <b style='color:#00d4ff'>LEVEL 2 ARCHITECTURE: REAL OBSERVATION + REAL-TIME VALIDATION + SIMULATED PROPAGATION</b><br>
        ACDS does not rely solely on previous scan history. It safely performs <b>non-destructive real-time validation</b>
        (host reachability, TCP connect ping, expected banner consistency) on authorized targets and feeds those live observations
        into the decision-based attack propagation engine.<br>
        <span style='color:#00ff88'><b>REAL OBSERVATION:</b></span> Discovered during network inventory &nbsp;|&nbsp;
        <span style='color:#00d4ff'><b>REAL-TIME VALIDATION:</b></span> Currently verified accepting/rejecting connections &nbsp;|&nbsp;
        <span style='color:#ff3355'><b>SIMULATION:</b></span> Modeled propagation condition evaluated in-memory.
        <br><span style='color:#ffd700'>🛡 100% NON-DESTRUCTIVE &amp; AUTHORIZED</span> — Zero exploits, zero brute force, zero payloads.
    </div>
    """, unsafe_allow_html=True)

    # ─────────────────────────────────────────────────────────────
    # LEVEL 2 LIVE VALIDATION CONTROL PANEL
    # ─────────────────────────────────────────────────────────────
    st.markdown("<b style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.82rem'>⚡ REAL-TIME DEFENSIVE VALIDATION (LIVE NETWORK)</b>", unsafe_allow_html=True)
    
    val_c1, val_c2, val_c3 = st.columns([2.2, 1.2, 1.0])
    all_nodes_list = list(st.session_state.G.nodes)
    real_nodes_list = [n for n in all_nodes_list if st.session_state.G.nodes[n].get("node_type") != "honeypot"]
    val_target_options = ["All Discovered Authorized Assets"] + real_nodes_list

    with val_c1:
        selected_val_target = st.selectbox(
            "Authorized Validation Scope",
            val_target_options,
            index=0,
            disabled=not real_nodes_list,
            key="live_val_target_scope",
            help="Select specific authorized asset or all discovered assets for safe, non-destructive real-time validation"
        )
    with val_c2:
        st.markdown("<div style='margin-top:28px'></div>", unsafe_allow_html=True)
        run_live_val_btn = st.button("⚡  VALIDATE LIVE STATE", use_container_width=True, disabled=not real_nodes_list)
    with val_c3:
        st.markdown("<div style='margin-top:28px'></div>", unsafe_allow_html=True)
        clear_val_btn = st.button("✕  CLEAR VALIDATION", use_container_width=True)

    if clear_val_btn:
        st.session_state.live_validation_results = {}
        st.session_state.last_validation_time = None
        st.session_state.validation_changes = []
        st.toast("Real-time validation cache cleared", icon="🧹")
        st.rerun()

    if run_live_val_btn and real_nodes_list:
        with st.spinner("Safely validating authorized target reachability and TCP ports..."):
            target_nodes = real_nodes_list if selected_val_target == "All Discovered Authorized Assets" else [selected_val_target]
            asset_targets_to_val = []
            for n in target_nodes:
                ndata = st.session_state.G.nodes.get(n, {})
                nip = ndata.get("ip")
                if not nip:
                    continue
                n_aid = ndata.get("asset_id") or generate_asset_id(ndata.get("mac", ""), nip, ndata.get("hostname", ""))
                n_ports = ndata.get("open_ports", [])
                asset_targets_to_val.append({
                    "asset_id": n_aid,
                    "ip": nip,
                    "expected_ports": n_ports,
                    "hostname": ndata.get("hostname"),
                    "services": ndata.get("services", [])
                })

            if asset_targets_to_val:
                val_snapshot = validate_multiple_assets(asset_targets_to_val, max_workers=4)
                
                # Diff against discovered baseline in graph
                discovered_baseline = {}
                for a in asset_targets_to_val:
                    discovered_baseline[a["asset_id"]] = {
                        "asset_id": a["asset_id"],
                        "ip": a["ip"],
                        "open_ports": a["expected_ports"],
                        "services": a.get("services", [])
                    }
                
                changes = diff_validation_against_discovery(discovered_baseline, val_snapshot)
                
                # Persist to database
                monitor_db.record_validation_snapshot(val_snapshot, changes)
                
                # Update session state
                st.session_state.live_validation_results.update(val_snapshot)
                st.session_state.last_validation_time = datetime.now(timezone.utc)
                st.session_state.validation_changes = changes

                # Alert if defense verified or exposure removed
                closed_count = sum(1 for c in changes if c.get("change_type") in ("SERVICE_EXPOSURE_REMOVED", "DEFENSE_VERIFIED"))
                if closed_count > 0:
                    st.toast(f"🛡 Defense Verified: {closed_count} attack surface port(s) confirmed CLOSED in real-time!", icon="🛡")
                else:
                    st.toast(f"⚡ Live validation complete — {len(val_snapshot)} asset(s) verified", icon="⚡")
                st.rerun()

    # ─────────────────────────────────────────────────────────────
    # REAL-TIME LIVE NETWORK STATE VISUALIZATION
    # ─────────────────────────────────────────────────────────────
    live_vals = st.session_state.get("live_validation_results", {})
    last_val_ts = st.session_state.get("last_validation_time")
    last_val_str = last_val_ts.strftime("%Y-%m-%d %H:%M:%S UTC") if last_val_ts else "Not yet performed (using discovery baseline)"

    if live_vals:
        st.markdown(f"""
        <div style='display:flex;justify-content:space-between;align-items:center;background:#06111a;border:1px solid #1a3a5c;padding:8px 14px;border-radius:4px;margin-bottom:12px;font-family:Share Tech Mono;font-size:0.68rem'>
            <span style='color:#00ff88'>● <b>REAL-TIME LIVE VALIDATION ACTIVE</b> ({len(live_vals)} targets evaluated)</span>
            <span style='color:#7ab8d4'>Last Validated: <b>{last_val_str}</b></span>
        </div>
        """, unsafe_allow_html=True)

        for n in real_nodes_list:
            ndata = st.session_state.G.nodes.get(n, {})
            n_aid = ndata.get("asset_id") or n
            nip = ndata.get("ip") or ""
            disp_name = ndata.get("display_name") or n

            val_res = live_vals.get(n_aid) or live_vals.get(nip)
            if not val_res:
                continue

            is_reach = val_res.get("reachable", False)
            reach_badge = "<span style='color:#00ff88;font-weight:bold'>✓ ONLINE</span>" if is_reach else "<span style='color:#ff3355;font-weight:bold'>✗ OFFLINE</span>"
            lat_txt = f"({val_res.get('latency_ms', 0):.1f} ms latency)" if val_res.get("latency_ms") is not None else ""
            method_txt = val_res.get("method", "tcp_syn_ping")
            ports_val = val_res.get("ports_validated") or val_res.get("ports", {})

            # Service validation rows
            port_rows_html = []
            disc_ports = ndata.get("open_ports", [])
            all_ports_to_show = sorted(list(set(disc_ports + [int(p) for p in ports_val])))
            
            for p in all_ports_to_show:
                p_int = int(p)
                svc_name = PORT_SERVICE_MAP.get(p_int, "TCP Service")
                was_disc = p_int in disc_ports
                pval_data = ports_val.get(p_int) or ports_val.get(str(p_int))
                
                if pval_data:
                    curr_state = (pval_data.get("status") or pval_data.get("state") or ("OPEN" if pval_data.get("open") else "CLOSED")).upper()
                    if curr_state == "OPEN":
                        status_badge = "<span style='color:#ff8c00;font-weight:bold'>● OPEN</span>"
                        val_badge = "<span style='background:rgba(255,140,0,0.15);color:#ff8c00;padding:2px 6px;border-radius:2px'>✓ STILL EXPOSED</span>"
                        sim_badge = "<span style='color:#00ff88'>✓ PROPAGATION CONDITION SATISFIED</span>"
                    elif curr_state == "HOST_UNREACHABLE" or not is_reach:
                        status_badge = "<span style='color:#ff3355;font-weight:bold'>✗ UNREACHABLE</span>"
                        val_badge = "<span style='background:rgba(255,51,85,0.15);color:#ff3355;padding:2px 6px;border-radius:2px'>✗ HOST OFFLINE</span>"
                        sim_badge = "<span style='color:#ff3355'>✗ ATTACK PATH INACTIVE (HOST OFFLINE)</span>"
                    else:
                        status_badge = "<span style='color:#00ff88;font-weight:bold'>○ CLOSED</span>"
                        val_badge = "<span style='background:rgba(0,255,136,0.15);color:#00ff88;padding:2px 6px;border-radius:2px'>✓ EXPOSURE REMOVED</span>"
                        sim_badge = "<span style='color:#ff3355'>✗ ATTACK SURFACE REMOVED</span>"
                else:
                    if not is_reach:
                        status_badge = "<span style='color:#ff3355;font-weight:bold'>✗ UNREACHABLE</span>"
                        val_badge = "<span style='background:rgba(255,51,85,0.15);color:#ff3355;padding:2px 6px;border-radius:2px'>✗ HOST OFFLINE</span>"
                        sim_badge = "<span style='color:#ff3355'>✗ ATTACK PATH INACTIVE (HOST OFFLINE)</span>"
                    else:
                        status_badge = "<span style='color:#7ab8d4'>UNVALIDATED</span>"
                        val_badge = "<span style='color:#7ab8d4'>Discovery Snapshot</span>"
                        sim_badge = "<span style='color:#7ab8d4'>Modeled</span>"

                disc_txt = f"TCP/{p_int} ({svc_name})" + (" [Discovered in scan]" if was_disc else "")
                port_rows_html.append(
                    f"<tr style='border-bottom:1px solid #142a3a'>"
                    f"<td style='padding:6px 8px;color:#e0f4ff'>{disc_txt}</td>"
                    f"<td style='padding:6px 8px'>{status_badge}</td>"
                    f"<td style='padding:6px 8px'>{val_badge}</td>"
                    f"<td style='padding:6px 8px'>{sim_badge}</td>"
                    f"</tr>"
                )

            rows_joined = "".join(port_rows_html) if port_rows_html else "<tr><td colspan='4' style='padding:6px;color:#3d6a8a'>No listening ports discovered or evaluated on this asset</td></tr>"
            ports_table = (
                f"<table style='width:100%;border-collapse:collapse;font-family:Share Tech Mono;font-size:0.68rem;margin-top:6px'>"
                f"<thead><tr style='color:#00d4ff;border-bottom:1px solid #00d4ff;text-align:left'>"
                f"<th style='padding:4px 8px'>REAL OBSERVATION (SCAN)</th>"
                f"<th style='padding:4px 8px'>PORT STATUS</th>"
                f"<th style='padding:4px 8px'>REAL-TIME VALIDATION</th>"
                f"<th style='padding:4px 8px'>SIMULATION IMPACT</th>"
                f"</tr></thead>"
                f"<tbody>{rows_joined}</tbody>"
                f"</table>"
            )

            card_html = (
                f"<div style='background:#091520;border:1px solid #1a3a5c;border-left:4px solid #00d4ff;padding:12px 16px;border-radius:4px;margin-bottom:10px'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                f"<span style='color:#e0f4ff;font-family:Orbitron,monospace;font-size:0.8rem;font-weight:bold'>🛰 LIVE STATE — {disp_name}</span>"
                f"<span style='font-family:Share Tech Mono;font-size:0.68rem'>Reachability: {reach_badge} {lat_txt}</span>"
                f"</div>"
                f"<div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin-top:4px'>"
                f"• <b>Asset ID:</b> <code>{n_aid}</code> &nbsp;|&nbsp; <b>Dynamic IP:</b> <code>{nip}</code> &nbsp;|&nbsp; <b>Method:</b> {method_txt}"
                f"</div>"
                f"{ports_table}"
                f"</div>"
            )
            st.markdown(card_html, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='background:#07121c;border:1px dashed #1a3a5c;padding:12px 16px;border-radius:4px;margin-bottom:12px;font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4'>
            ℹ <i>Live validation not yet executed this session. Click <b>⚡ VALIDATE LIVE STATE</b> above to test authorized targets in real time. (Simulation will fall back to discovery snapshot with clear labeling if live validation is omitted).</i>
        </div>
        """, unsafe_allow_html=True)

    # Validation Changes Timeline if any
    val_changes = st.session_state.get("validation_changes", [])
    if val_changes:
        st.markdown("<b style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.75rem'>🔁 REAL-TIME CHANGE DETECTION &amp; DEFENSE VERIFICATION LOG</b>", unsafe_allow_html=True)
        for ch in val_changes[:5]:
            ch_type = ch.get("change_type", "CHANGE")
            ch_color = "#00ff88" if "REMOVED" in ch_type or "VERIFIED" in ch_type else "#ff3355"
            st.markdown(f"""
            <div style='background:#0a1926;border-left:3px solid {ch_color};padding:6px 10px;margin-bottom:6px;font-family:Share Tech Mono;font-size:0.68rem;color:#e0f4ff'>
                <span style='color:{ch_color};font-weight:bold'>[{ch_type}]</span> {ch.get('description', '')}
                <span style='color:#3d6a8a;float:right'>{ch.get('timestamp', '')[:19]}</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)

    # ─────────────────────────────────────────────────────────────
    # CONTROLS BAR: Foothold Selection & Run Simulation
    # ─────────────────────────────────────────────────────────────
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2.5, 1.2, 1.0])
    all_sim_nodes = list(st.session_state.G.nodes)
    if st.session_state.network_mode == "Simulated Lab":
        all_sim_nodes = [n for n in all_sim_nodes if st.session_state.G.nodes[n].get("node_type") != "honeypot"]

    with ctrl_col1:
        entry_node_prop = st.selectbox(
            "Attacker Foothold / Entry Point Asset",
            all_sim_nodes,
            index=min(1, len(all_sim_nodes) - 1) if all_sim_nodes else 0,
            disabled=not all_sim_nodes,
            key="prop_sim_entry_select",
            help="Select the initial compromised asset where the threat actor established a foothold"
        )
    with ctrl_col2:
        st.markdown("<div style='margin-top:28px'></div>", unsafe_allow_html=True)
        run_prop_btn = st.button("▶  RUN PROPAGATION SIM", use_container_width=True, disabled=not all_sim_nodes, key="btn_run_prop_sim")
    with ctrl_col3:
        st.markdown("<div style='margin-top:28px'></div>", unsafe_allow_html=True)
        reset_prop_btn = st.button("↺  RESET SIMULATION", use_container_width=True, key="btn_reset_prop_sim")

    if reset_prop_btn:
        for node in st.session_state.G.nodes:
            st.session_state.G.nodes[node]["compromised"] = False
        st.session_state.simulation_done = False
        st.session_state.timeline = []
        st.session_state.decision_log = []
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

    if run_prop_btn and entry_node_prop:
        st.session_state.last_entry_node = entry_node_prop
        for node in st.session_state.G.nodes:
            st.session_state.G.nodes[node]["compromised"] = False

        # Feed real-time live validation snapshot into the propagation decision engine
        live_val_snapshot = st.session_state.get("live_validation_results") or None

        timeline, decision_log, compromised, uncompromised, successful_paths, blocked_failed_paths, stats = simulate_decision_based_propagation(
            st.session_state.G, entry_node_prop, seed=random.randint(1, 9999),
            ids_deployed=st.session_state.ids_deployed,
            segmentation_applied=st.session_state.segmentation_applied,
            live_validation=live_val_snapshot,
        )

        honeypot_triggered = any(
            entry.get("ntype") == "honeypot" and entry.get("success") for entry in timeline
        )

        st.session_state.timeline = timeline
        st.session_state.decision_log = decision_log
        st.session_state.compromised = compromised
        st.session_state.honeypot_triggered = honeypot_triggered
        st.session_state.simulation_done = True
        st.session_state.current_anim_node = None

        risk_score, blast_details = calculate_risk(st.session_state.G, compromised, timeline, honeypot_triggered, stats)
        st.session_state.risk_score = risk_score
        st.session_state.blast_details = blast_details
        st.session_state.attack_stats = stats

        if honeypot_triggered:
            honeypot_engine.record_trigger(
                source_node=entry_node_prop, decoy_node="Honeypot (decoy)",
                event_type="simulated_probe",
                details="Simulated attacker reached the decoy node during attack propagation simulation.",
                risk_before=risk_score - 15 if risk_score is not None else None,
                risk_after=risk_score,
            )
        st.session_state.adaptive_feedback = honeypot_engine.apply_adaptive_feedback(risk_score)
        st.session_state.overall_acds_risk = calculate_overall_acds_risk(st.session_state.G, risk_score)

        if st.session_state.risk_before_defense is None:
            st.session_state.risk_before_defense = risk_score
            st.session_state.blast_before_defense = blast_details
            st.session_state.overall_acds_risk_before = st.session_state.overall_acds_risk
            st.session_state.mitre_before_defense = {
                e["mitre_code"]: e["mitre_desc"] for e in timeline if e["success"]
            }

        st.session_state.defense_actions = get_defense_actions(st.session_state.G, compromised, risk_score)
        selected, total_reduction, remaining = greedy_defense_selection(st.session_state.defense_actions, st.session_state.budget)
        st.session_state.selected_defenses = selected
        st.session_state.attack_log = generate_attack_log(timeline, honeypot_triggered)
        st.session_state.blast_radius_last_computed = datetime.now(timezone.utc)
        record_scan_history(st.session_state.G, "Post-simulation")
        persist_dynamic_risk_pipeline("SIMULATION")
        st.rerun()

    # ─────────────────────────────────────────────────────────────
    # SIMULATION OUTPUT & DECISION VISUALIZATION
    # ─────────────────────────────────────────────────────────────
    if not st.session_state.get("simulation_done") or not st.session_state.get("decision_log"):
        st.markdown("""
        <div style='background:#0a1520;border:1px solid #1a3a5c;border-left:3px solid #00d4ff;
             padding:24px;font-family:Share Tech Mono;font-size:0.78rem;line-height:2;
             text-align:center;margin-top:16px'>
            <div style='color:#00d4ff;font-size:0.95rem;font-family:Orbitron,monospace;letter-spacing:3px;margin-bottom:12px'>
                READY TO SIMULATE ATTACK PROPAGATION
            </div>
            <div style='color:#7ab8d4'>
                1. Click <b>⚡ VALIDATE LIVE STATE</b> to safely test authorized target reachability &amp; open ports in real time.<br>
                2. Select an <b>Attacker Foothold / Entry Point Asset</b> in the controls above.<br>
                3. Click <b>▶ RUN PROPAGATION SIM</b> to evaluate candidate attack paths against live-validated conditions.
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    dlog = st.session_state.get("decision_log", [])
    entry_item = dlog[0] if dlog else {}
    eval_items = dlog[1:] if len(dlog) > 1 else []
    stats = st.session_state.get("attack_stats", {})

    # Top Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("INITIAL FOOTHOLD", entry_item.get("target", "Asset")[:18])
    with m2:
        st.metric("CANDIDATES EVALUATED", len(eval_items))
    with m3:
        st.metric("COMPROMISED ASSETS", len(st.session_state.get("compromised", [])))
    with m4:
        blocked_count = sum(1 for d in eval_items if "BLOCKED" in d.get("decision", ""))
        st.metric("BLOCKED BY DEFENSE", blocked_count)
    with m5:
        st.metric("MAX LATERAL HOPS", stats.get("max_lateral_hops", 0))

    st.markdown('<hr style="border-color:#1a3a5c;margin:14px 0">', unsafe_allow_html=True)

    # 1. INITIAL COMPROMISE CARD
    st.markdown("<b style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.82rem'>🎯 INITIAL ACCESS FOOTHOLD (STEP 1)</b>", unsafe_allow_html=True)
    st.markdown(f"""
    <div style='background:#0d1f2d;border:1px solid #00ff88;border-left:4px solid #00ff88;padding:12px 16px;border-radius:4px;margin-bottom:16px'>
        <div style='display:flex;justify-content:space-between;align-items:center'>
            <span style='color:#00ff88;font-family:Orbitron,monospace;font-size:0.85rem;font-weight:bold'>
                ✓ COMPROMISE INITIALIZED — {entry_item.get("target")}
            </span>
            <span style='background:rgba(0,255,136,0.15);color:#00ff88;padding:2px 8px;border-radius:3px;font-family:Share Tech Mono;font-size:0.68rem'>
                PROBABILITY: 100%
            </span>
        </div>
        <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#e0f4ff;margin-top:6px;line-height:1.7'>
            • <b>Asset ID:</b> <code>{entry_item.get("target_id", "-")}</code> &nbsp;|&nbsp; <b>IP:</b> <code>{entry_item.get("target_ip", "-")}</code><br>
            • <b>Initial Access Vector:</b> {entry_item.get("technique")}<br>
            • <b>Vulnerability / Foothold:</b> {entry_item.get("vulnerability")}<br>
            • <b>Explanation:</b> {entry_item.get("reason")}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 2. CANDIDATE PROPAGATION EVALUATION (STEP 2+)
    st.markdown("<b style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.82rem'>🔗 CANDIDATE PROPAGATION EVALUATION &amp; DECISIONS</b>", unsafe_allow_html=True)

    if not eval_items:
        st.markdown("""
        <div style='background:#0a1926;border:1px solid #ffaa33;border-left:4px solid #ffaa33;padding:16px 20px;border-radius:4px;margin-bottom:16px'>
            <div style='color:#ffaa33;font-family:Orbitron,monospace;font-size:0.85rem;font-weight:bold'>
                ⚠️ NO VALID SIMULATED PROPAGATION PATH IDENTIFIED FROM CURRENT FOOTHOLD
            </div>
            <div style='font-family:Share Tech Mono;font-size:0.75rem;color:#e0f4ff;margin-top:6px;line-height:1.8'>
                The initial compromised asset has no exploitable listening services or accessible lateral paths to other discovered endpoints on the network.
                <br>• <b>Exploitation Status:</b> Contained at entry foothold.
                <br>• <b>Empirical Evidence:</b> Neighboring assets have no open ports matching known lateral movement vectors (e.g., SMB/445, RDP/3389, SSH/22, DB ports) or are protected by host isolation.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        for item in eval_items:
            dec = item.get("decision", "")
            is_comp = "COMPROMISE POSSIBLE" in dec
            is_blocked = "BLOCKED" in dec
            is_no_path = "NO VALID PATH" in dec
            is_live_val = item.get("live_validated", False)
            live_pt_state = item.get("live_port_state", "")

            if is_comp:
                border_color = "#ff3355"
                badge_bg = "rgba(255,51,85,0.15)"
                badge_color = "#ff3355"
                status_icon = "💥"
            elif is_blocked:
                border_color = "#9b5de5"
                badge_bg = "rgba(155,93,229,0.15)"
                badge_color = "#c77dff"
                status_icon = "🛡"
            elif is_no_path:
                border_color = "#3d6a8a"
                badge_bg = "rgba(61,106,138,0.15)"
                badge_color = "#7ab8d4"
                status_icon = "⊘"
            else:
                border_color = "#ff8c00"
                badge_bg = "rgba(255,140,0,0.15)"
                badge_color = "#ffaa33"
                status_icon = "✗"

            val_badge_html = (
                f"<span style='background:rgba(0,255,136,0.15);color:#00ff88;padding:2px 6px;border-radius:2px;font-size:0.62rem;margin-left:8px'>⚡ LIVE VALIDATED: {live_pt_state}</span>"
                if is_live_val
                else "<span style='background:rgba(61,106,138,0.15);color:#7ab8d4;padding:2px 6px;border-radius:2px;font-size:0.62rem;margin-left:8px'>[DISCOVERY SNAPSHOT]</span>"
            )

            st.markdown(f"""
            <div style='background:#091520;border:1px solid {border_color};border-left:4px solid {border_color};padding:12px 16px;border-radius:4px;margin-bottom:10px'>
                <div style='display:flex;justify-content:space-between;align-items:center'>
                    <div>
                        <span style='color:#e0f4ff;font-family:Orbitron,monospace;font-size:0.8rem;font-weight:bold'>
                            STEP {item.get("step")} &nbsp;·&nbsp; {item.get("source")} ➔ {item.get("target")}
                        </span>
                        {val_badge_html}
                    </div>
                    <span style='background:{badge_bg};color:{badge_color};padding:2px 8px;border-radius:3px;font-family:Share Tech Mono;font-size:0.68rem;font-weight:bold'>
                        {status_icon} {dec} ({item.get("probability", "0%")})
                    </span>
                </div>
                <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;margin-top:6px;line-height:1.7'>
                    • <b>Path:</b> <code>{item.get("path")}</code><br>
                    • <b>Evaluated Service:</b> <span style='color:#00d4ff'>{item.get("service")}</span> &nbsp;|&nbsp; <b>Vulnerability / Condition:</b> <span style='color:#ffd700'>{item.get("vulnerability")}</span><br>
                    • <b>MITRE ATT&CK:</b> {item.get("technique")}<br>
                    • <b>Decision Rationale:</b> <span style='color:#e0f4ff'>{item.get("reason")}</span>
                </div>
                {f"<div style='background:rgba(255,51,85,0.1);padding:4px 8px;border-radius:2px;font-family:Share Tech Mono;font-size:0.65rem;color:#ff3355;margin-top:6px'>🔗 Target asset compromised — chained as new attack source for subsequent lateral propagation evaluations</div>" if is_comp else ""}
            </div>
            """, unsafe_allow_html=True)

    # 3. STRUCTURED DECISION LOG TABLE
    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)
    st.markdown("<b style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.82rem'>📋 STRUCTURED ATTACK PROPAGATION DECISION LOG</b>", unsafe_allow_html=True)
    table_rows = []
    for d in dlog:
        table_rows.append({
            "STEP": d.get("step"),
            "SOURCE ASSET": d.get("source"),
            "TARGET ASSET": d.get("target"),
            "EVALUATED SERVICE / PORT": d.get("service"),
            "VULNERABILITY / CONDITION": d.get("vulnerability"),
            "DECISION OUTCOME": d.get("decision"),
            "PROBABILITY": d.get("probability"),
            "LIVE VALIDATED": "YES" if d.get("live_validated") else "NO (Snapshot)",
            "RESULT STATUS": d.get("result_status"),
            "RATIONALE": d.get("reason")[:75] + "..." if len(d.get("reason", "")) > 75 else d.get("reason")
        })
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

    # 4. SIMULATION-DRIVEN RISK PRIORITIZATION
    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)
    st.markdown("<b style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.82rem'>🎯 SIMULATION-DRIVEN RISK PRIORITIZATION</b>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;margin-bottom:12px'>
        ACDS prioritizes risk based on <b>actual simulated attack leverage</b> rather than CVSS in isolation.
    </div>
    """, unsafe_allow_html=True)

    comp_nodes = list(st.session_state.get("compromised", []))
    if not comp_nodes:
        st.info("No compromised nodes in current simulation.")
    else:
        p_idx = 1
        for cn in comp_nodes:
            cdata = st.session_state.G.nodes.get(cn, {})
            cdisplay = cdata.get("display_name", cn)
            cscore = cdata.get("risk_score", 50.0)
            csev = cdata.get("risk_severity", "MEDIUM")
            cports = cdata.get("open_ports", [])
            ccves = cdata.get("cve_findings", [])
            csev_color = "#ff3355" if csev == "CRITICAL" else "#ff8c00" if csev == "HIGH" else "#ffd700" if csev == "MEDIUM" else "#00ff88"

            why_txt = (
                f"Asset was compromised during simulation via {cdata.get('services', ['service exposure'])[0]} "
                f"and provides lateral propagation access to {len(cdata.get('open_ports', []))} reachable listening ports."
            )
            action_txt = (
                f"Apply host firewall rules to restrict sensitive ports ({', '.join(str(p) for p in cports[:3])}) "
                f"and patch identified CVEs ({ccves[0]['cve_id'] if ccves else 'harden service configuration'})."
            )

            st.markdown(f"""
            <div style='background:#091520;border-left:4px solid {csev_color};border:1px solid #1a3a5c;padding:12px 16px;border-radius:4px;margin-bottom:10px'>
                <div style='display:flex;justify-content:space-between;align-items:center'>
                    <div style='color:{csev_color};font-family:Orbitron,monospace;font-size:0.82rem;font-weight:bold'>
                        #{p_idx} — HIGH RISK VECTOR ON {cdisplay}
                    </div>
                    <div style='background:rgba(255,255,255,0.05);padding:2px 8px;border-radius:3px;font-family:Share Tech Mono;font-size:0.68rem;color:{csev_color}'>
                        RISK: {cscore}/100 ({csev})
                    </div>
                </div>
                <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#e0f4ff;margin-top:6px;line-height:1.7'>
                    • <b>Simulation Leverage:</b> {why_txt}<br>
                    • <b>Recommended Hardening:</b> <span style='color:#00ff88'>{action_txt}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            p_idx += 1


# ─────────────────────────────────────────────────────────────────
# 🧭 MODERN TAB-BASED CYBER-DEFENSE LIFECYCLE NAVIGATION
# ─────────────────────────────────────────────────────────────────
tab_exec, tab_assets_vulns, tab_prop_sim, tab_sim_map, tab_defense, tab_alerts = st.tabs([
    "🏠 Executive Overview",
    "🧬 Discover & Assess",
    "⚔️ Attack Propagation Simulator",
    "🗺️ Attack Graph & Blast Radius",
    "🛡️ Defense Optimization & Verification",
    "🚨 Alerts & Reports",
])

# ═════════════════════════════════════════════════════════════════
# TAB 2: ⚔️ DYNAMIC DECISION-BASED ATTACK PROPAGATION SIMULATOR
# ═════════════════════════════════════════════════════════════════
with tab_prop_sim:
    render_decision_propagation_tab()

# ═════════════════════════════════════════════════════════════════
# TAB 1: 🏠 EXECUTIVE DASHBOARD
# ═════════════════════════════════════════════════════════════════
with tab_exec:
    st.markdown('<div class="section-header">🏠 EXECUTIVE CYBER DASHBOARD</div>', unsafe_allow_html=True)
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        st.metric("TOTAL ASSETS", _total_assets)
    with k2:
        st.metric("CRITICAL ASSETS", _critical_assets)
    with k3:
        st.metric("ACTIVE VULNERABILITIES", _active_vulns)
    with k4:
        st.metric("OVERALL ACDS RISK", _overall_display)
    with k5:
        st.metric("ACTIVE ALERTS", _active_alerts)
    with k6:
        st.metric("AVERAGE RISK", f"{asset_metrics['average_risk']}")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("HIGH RISK", asset_metrics["high"])
    with m2:
        st.metric("MEDIUM RISK", asset_metrics["medium"])
    with m3:
        st.metric("LOW RISK", asset_metrics["low"])
    with m4:
        st.metric("SERVERS", asset_metrics["servers"])
    with m5:
        st.metric("OTHER DEVICES", asset_metrics["other_devices"])

    st.markdown('<hr style="border-color:#1a3a5c;margin:12px 0 16px 0">', unsafe_allow_html=True)

    st.markdown('<div class="section-header">📝 EXECUTIVE BRIEFING (PLAIN ENGLISH)</div>', unsafe_allow_html=True)
    summary_html = build_executive_summary(
        st.session_state.G, st.session_state.compromised, st.session_state.risk_score,
        st.session_state.blast_details, st.session_state.get("last_entry_node") or (entry_node if 'entry_node' in locals() else None),
    )
    st.markdown(f"<div class='exec-summary'>{summary_html}</div>", unsafe_allow_html=True)

    # Overall ACDS Risk Formula Breakdown
    st.markdown('<div class="section-header">🎯 OVERALL ACDS RISK FORMULA BREAKDOWN</div>', unsafe_allow_html=True)
    blast_ts = st.session_state.get("blast_radius_last_computed")
    blast_ts_txt = blast_ts.strftime("%Y-%m-%d %H:%M:%S UTC") if blast_ts else "not yet computed"
    if overall['status'] == 'COMPLETE':
        ov_color = "#ff3355" if overall['overall_score'] > 70 else "#ff8c00" if overall['overall_score'] > 40 else "#00ff88"
        st.markdown(f"""
        <div style='background:#0d1f2d;border:1px solid {ov_color};padding:16px;margin-bottom:10px'>
            <div style='font-family:Orbitron,monospace;font-size:2rem;color:{ov_color};text-align:center'>{overall['overall_score']} / 100</div>
            <div style='font-family:Share Tech Mono;font-size:0.65rem;color:{ov_color};text-align:center;letter-spacing:2px'>{overall['severity']}</div>
            <div style='display:flex;justify-content:space-around;margin-top:10px;font-family:Share Tech Mono;font-size:0.62rem;color:#7ab8d4;flex-wrap:wrap;gap:8px'>
                <div>Avg Asset Risk<br><span style='color:#00d4ff'>{overall['asset_component']} &times; {int(overall['asset_weight']*100)}%</span></div>
                <div>Blast Radius<br><span style='color:#ff8c00'>{overall['blast_component']} &times; {int(overall['blast_weight']*100)}%</span></div>
                <div>Critical Asset Exposure<br><span style='color:#ff3355'>{overall['critical_exposure_component']} &times; {int(overall['critical_exposure_weight']*100)}%</span></div>
                <div>Network Exposure<br><span style='color:#ffd700'>{overall['network_exposure_component']} &times; {int(overall['network_exposure_weight']*100)}%</span></div>
                <div>Total<br><span style='color:{ov_color}'>{overall['overall_score']} / 100</span></div>
            </div>
            <div style='font-family:Share Tech Mono;font-size:0.58rem;color:#3d6a8a;text-align:center;margin-top:8px'>
                Overall ACDS Risk = Avg Asset Risk &times; {overall['asset_weight']} + Blast Radius &times; {overall['blast_weight']}
                + Critical Asset Exposure &times; {overall['critical_exposure_weight']} + Network Exposure &times; {overall['network_exposure_weight']}
            </div>
            <div style='font-family:Share Tech Mono;font-size:0.58rem;color:#ff3355;text-align:center;margin-top:6px;letter-spacing:1px'>
                SIMULATED -- NO REAL ATTACK TRAFFIC &nbsp;&middot;&nbsp; Blast Radius last computed: {blast_ts_txt}
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info(f"Overall ACDS Risk: {overall['status']} — Avg Asset Risk {overall['asset_component']}/100, "
                f"Critical Asset Exposure {overall['critical_exposure_component']}/100, "
                f"Network Exposure {overall['network_exposure_component']}/100. Run an attack simulation in the **⚔️ Attack Simulation & Live Map** tab to compute the Blast Radius component.")

    st.markdown('<hr style="border-color:#1a3a5c;margin:12px 0 16px 0">', unsafe_allow_html=True)
    st.markdown('<div class="section-header">📈 RISK TREND &amp; DISTRIBUTION</div>', unsafe_allow_html=True)
    trend_col, dist_col = st.columns([1, 1], gap="medium")

    with trend_col:
        st.markdown("<div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin-bottom:4px'>Overall Risk Trend</div>", unsafe_allow_html=True)
        trend_rows = monitor_db.get_overall_risk_trend(limit=100)
        if trend_rows:
            trend_df = pd.DataFrame(trend_rows)
            trend_df["timestamp"] = pd.to_datetime(trend_df["timestamp"]).dt.strftime("%m-%d %H:%M")
            trend_df = trend_df.set_index("timestamp")[["overall_risk"]].rename(columns={"overall_risk": "Overall ACDS Risk"})
            st.line_chart(trend_df, height=220)
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#3d6a8a">'
                'No risk history yet — run a scan or simulation to seed the trend.</div>', unsafe_allow_html=True)

    with dist_col:
        st.markdown("<div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin-bottom:4px'>Asset Risk Distribution</div>", unsafe_allow_html=True)
        latest_rows = monitor_db.get_latest_asset_risk_rows()
        if latest_rows:
            buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for r in latest_rows:
                if r.get("asset_risk") is None:
                    continue
                buckets[severity_from_score(r["asset_risk"])] += 1
            dist_df = pd.DataFrame({"Assets": buckets}, index=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            st.bar_chart(dist_df, height=220)
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#3d6a8a">'
                'No risk history yet.</div>', unsafe_allow_html=True)

    st.markdown("<div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin:14px 0 4px'>Top 10 Highest Risk Assets</div>", unsafe_allow_html=True)
    latest_rows = monitor_db.get_latest_asset_risk_rows()
    if latest_rows:
        top10 = sorted([r for r in latest_rows if r.get("asset_risk") is not None],
                        key=lambda r: r["asset_risk"], reverse=True)[:10]
        rows_html = "".join(
            f"<tr style='border-bottom:1px solid #1a3a5c'>"
            f"<td style='padding:4px 6px'>{r.get('asset_ip') or '-'}</td>"
            f"<td style='padding:4px 6px'>{r.get('hostname') or '-'}</td>"
            f"<td style='padding:4px 6px;color:{_ALERT_SEVERITY_COLOR.get(severity_from_score(r['asset_risk']), '#7ab8d4')}'>{r['asset_risk']} ({severity_from_score(r['asset_risk'])})</td>"
            f"<td style='padding:4px 6px'>{CRITICALITY_LABELS.get(_safe_int(r.get('criticality')), '-')}</td>"
            f"<td style='padding:4px 6px'>{(r.get('last_seen') or '')[:19]}</td>"
            f"</tr>" for r in top10
        )
        st.markdown(f"""
        <table style="width:100%;border-collapse:collapse;font-family:Share Tech Mono;
               font-size:0.65rem;color:#7ab8d4">
        <thead><tr style="color:#00d4ff;border-bottom:1px solid #00d4ff">
        <th style='text-align:left;padding:4px 6px'>IP</th>
        <th style='text-align:left;padding:4px 6px'>Hostname</th>
        <th style='text-align:left;padding:4px 6px'>Risk</th>
        <th style='text-align:left;padding:4px 6px'>Criticality</th>
        <th style='text-align:left;padding:4px 6px'>Last Seen</th>
        </tr></thead>
        <tbody>{rows_html}</tbody>
        </table>
        """, unsafe_allow_html=True)
    else:
        st.markdown(
            '<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#3d6a8a">'
            'No risk history yet.</div>', unsafe_allow_html=True)

# ═════════════════════════════════════════════════════════════════
# TAB 2: ⚔️ ATTACK SIMULATION & LIVE TOPOLOGY MAP
# ═════════════════════════════════════════════════════════════════
with tab_sim_map:
    st.markdown('<div class="section-header">⚔️ ATTACK PATH SIMULATION &amp; LIVE TOPOLOGY MAP</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style='background:rgba(255,51,85,0.06);border:1px solid #ff3355;padding:8px 14px;
         font-family:Share Tech Mono;font-size:0.65rem;color:#ff3355;letter-spacing:1px;margin-bottom:12px'>
    SIMULATION ONLY &nbsp;•&nbsp; NO REAL ATTACK TRAFFIC GENERATED &nbsp;•&nbsp; NO EXPLOITATION PERFORMED
    </div>
    """, unsafe_allow_html=True)

    sim_ctrl1, sim_ctrl2, sim_ctrl3 = st.columns([2, 1, 1])
    all_sim_nodes = list(st.session_state.G.nodes)
    if st.session_state.network_mode == "Simulated Lab":
        all_sim_nodes = [n for n in all_sim_nodes if st.session_state.G.nodes[n].get("node_type") != "honeypot"]

    with sim_ctrl1:
        entry_node_sim = st.selectbox(
            "Attacker Foothold / Entry Point",
            all_sim_nodes,
            index=min(1, len(all_sim_nodes) - 1) if all_sim_nodes else 0,
            disabled=not all_sim_nodes,
            key="sim_tab_entry_node",
            help="The system where the attacker first gained simulated access",
        )
    with sim_ctrl2:
        run_sim_btn = st.button("▶  RUN SIMULATION", use_container_width=True, disabled=not all_sim_nodes, key="btn_run_sim_map")
    with sim_ctrl3:
        reset_sim_btn = st.button("↺  RESET SIMULATION", use_container_width=True, key="btn_reset_sim_map")

    if reset_sim_btn:
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

    if run_sim_btn and entry_node_sim:
        st.session_state.last_entry_node = entry_node_sim
        for node in st.session_state.G.nodes:
            st.session_state.G.nodes[node]["compromised"] = False

        timeline, compromised, honeypot_triggered, attack_stats = simulate_attack(
            st.session_state.G, entry_node_sim, seed=random.randint(1, 9999),
            ids_deployed=st.session_state.ids_deployed,
            segmentation_applied=st.session_state.segmentation_applied,
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

        if honeypot_triggered:
            honeypot_engine.record_trigger(
                source_node=entry_node_sim, decoy_node="Honeypot (decoy)",
                event_type="simulated_probe",
                details="Simulated attacker reached the decoy node during attack simulation.",
                risk_before=risk_score - 15 if risk_score is not None else None,
                risk_after=risk_score,
            )
        st.session_state.adaptive_feedback = honeypot_engine.apply_adaptive_feedback(risk_score)
        st.session_state.overall_acds_risk = calculate_overall_acds_risk(st.session_state.G, risk_score)

        if st.session_state.risk_before_defense is None:
            st.session_state.risk_before_defense = risk_score
            st.session_state.blast_before_defense = blast_details
            st.session_state.overall_acds_risk_before = st.session_state.overall_acds_risk
            st.session_state.mitre_before_defense = {
                e["mitre_code"]: e["mitre_desc"] for e in timeline if e["success"]
            }

        st.session_state.defense_actions = get_defense_actions(st.session_state.G, compromised, risk_score)
        selected, total_reduction, remaining = greedy_defense_selection(st.session_state.defense_actions, st.session_state.budget)
        st.session_state.selected_defenses = selected
        st.session_state.attack_log = generate_attack_log(timeline, honeypot_triggered)
        st.session_state.blast_radius_last_computed = datetime.now(timezone.utc)
        record_scan_history(st.session_state.G, "Post-simulation")
        persist_dynamic_risk_pipeline("SIMULATION")
        st.rerun()

    st.markdown('<hr style="border-color:#1a3a5c;margin:12px 0 16px 0">', unsafe_allow_html=True)

    st.markdown('<div class="section-header">🗺 LIVE EXPOSURE &amp; ATTACK TOPOLOGY MAP &amp; ASSET INTELLIGENCE</div>', unsafe_allow_html=True)

    map_c1, map_c2 = st.columns([1.1, 0.9])
    with map_c1:
        topo_edge_filter = st.selectbox(
            "Path Filter",
            ["Clean View (Focus on Attack & Critical Paths)", "All Potential Paths (Full Mesh)", "Attack Paths Only"],
            index=0,
            key="topo_filter_select",
            help="Clean view prevents visual clutter by focusing on attack vectors, high-risk assets, and active paths."
        )
    with map_c2:
        topo_layout = st.selectbox(
            "Layout",
            ["Force-Directed (Dynamic)", "Hierarchical (Tiered)"],
            index=0,
            key="topo_layout_select",
        )

    st.markdown(f"""
    <div style='display:flex;justify-content:space-between;font-family:Share Tech Mono;font-size:0.6rem;color:#3d6a8a;margin-bottom:6px'>
        <span>Edges = modeled potential reachability. Click any node in the map to inspect in real-time.</span>
        <span style='color:#00d4ff'><b>{len(st.session_state.G.nodes)}</b> Assets • <b>{len(st.session_state.G.edges)}</b> Modeled Paths</span>
    </div>
    """, unsafe_allow_html=True)

    graph_placeholder = st.empty()
    html_graph = render_graph(st.session_state.G, compromised_set=st.session_state.compromised,
                               current_node=st.session_state.current_anim_node, show_honeypot=show_honeypot if 'show_honeypot' in locals() else True,
                               new_exposure_edges=st.session_state.get("new_exposure_edges"),
                               edge_filter=topo_edge_filter, layout_mode=topo_layout)
    with graph_placeholder:
        st.components.v1.html(html_graph, height=590, scrolling=False)

    st.markdown("""
    <div style='display:flex;gap:12px;font-family:Share Tech Mono,monospace;font-size:0.62rem;margin-top:8px;margin-bottom:16px;flex-wrap:wrap;background:#050a0f;padding:8px 10px;border:1px solid #1a3a5c;border-radius:4px;'>
        <span><span style='color:#00d4ff'>■</span> ASSET</span>
        <span><span style='color:#ff3355'>■</span> COMPROMISED</span>
        <span><span style='color:#ff8c00'>■</span> ACTIVE ATTACK</span>
        <span><span style='color:#00ff88'>■</span> ISOLATED</span>
        <span><span style='color:#ffd700'>★</span> HONEYPOT</span>
        <span><span style='color:#ff3355'>➔</span> ATTACK VECTOR</span>
        <span><span style='color:#ff8c00'>┄➔</span> ATTACK FRONTIER</span>
        <span><span style='color:#ffd700'>➔</span> NEW EXPOSURE</span>
        <span><span style='color:#00d4ff'>➔</span> CORE INFRA</span>
        <span><span style='color:#2d5f8c'>➔</span> LATERAL PATH</span>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.simulation_done:
        col_sim_blast, col_sim_timeline = st.columns([1.0, 1.0], gap="large")

        with col_sim_blast:
            st.markdown('<div class="section-header">📊 SIMULATED BLAST RADIUS</div>', unsafe_allow_html=True)
            rs = st.session_state.risk_score
            bd = st.session_state.blast_details
            risk_color = "#ff3355" if rs > 70 else "#ff8c00" if rs > 40 else "#00ff88"
            risk_label = severity_from_score(rs)

            st.markdown(f"""
            <div style='background:#0d1f2d;border:1px solid {risk_color};padding:14px;text-align:center;margin-bottom:12px'>
                <div style='font-family:Orbitron,monospace;font-size:2.2rem;color:{risk_color};
                            text-shadow:0 0 16px {risk_color};font-weight:900'>{rs}</div>
                <div style='font-family:Share Tech Mono;font-size:0.68rem;color:{risk_color};letter-spacing:3px'> / 100 — {risk_label}</div>
                <div class="risk-bar-container" style='margin-top:8px'>
                    <div class="risk-bar" style='width:{rs}%;background:linear-gradient(90deg,#003d5c,{risk_color})'></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            hp_penalty_html = "<div style='color:#ffd700;margin-top:6px'>⚠ HONEYPOT TRIGGERED (simulated): +15 risk penalty</div>" if st.session_state.honeypot_triggered else ""
            st.markdown(f"""
            <div style='font-family:Share Tech Mono;font-size:0.7rem;line-height:1.8;background:#0a1520;
                 border:1px solid #1a3a5c;padding:10px 14px;margin-bottom:12px'>
                <div style='color:#3d6a8a'>FORMULA: R = 0.3×spread + 0.5×critical_impact + 0.2×depth</div>
                <div>Spread (0.3): <span style='color:#00d4ff;float:right'>{bd.get("spread",0)}%</span></div>
                <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("spread",0)}%;background:#00d4ff'></div></div>
                <div>Critical Impact (0.5): <span style='color:#ff8c00;float:right'>{bd.get("critical_impact",0)}%</span></div>
                <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("critical_impact",0)}%;background:#ff8c00'></div></div>
                <div>Depth (0.2): <span style='color:#ffd700;float:right'>{bd.get("depth",0)}%</span></div>
                <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("depth",0)}%;background:#ffd700'></div></div>
                <div style='display:flex;justify-content:space-between;margin-top:6px'>
                    <span>Controlled: <b style='color:#ff3355'>{bd.get("systems_controlled", bd.get("compromised_count",0))}/{bd.get("total_real_nodes",0)}</b></span>
                    <span>Critical Reached: <b style='color:#ff3355'>{bd.get("critical_assets_reached", 0)}</b></span>
                </div>
                <div style='display:flex;justify-content:space-between;margin-top:2px'>
                    <span>Lateral Hops: <b style='color:#ffd700'>{bd.get("max_lateral_hops", 0)}</b></span>
                    <span>Priv Esc: <b style='color:#ff8c00'>{bd.get("privilege_escalations", 0)}</b></span>
                </div>
                {hp_penalty_html}
            </div>
            """, unsafe_allow_html=True)

            paths = bd.get("attack_paths", [])
            if paths:
                with st.expander("📍 SIMULATED ATTACK PATHS", expanded=False):
                    for path in paths[:4]:
                        path_str = " → ".join(p.replace("\n", " / ") for p in path)
                        st.markdown(
                            f'<div style="font-family:Share Tech Mono;font-size:0.65rem;color:#7ab8d4;'
                            f'padding:4px 8px;margin:2px 0;background:#060d15;border-left:2px solid #ff3355">{path_str}</div>',
                            unsafe_allow_html=True,
                        )

        with col_sim_timeline:
            st.markdown('<div class="section-header">⏱ SIMULATED ATTACK TIMELINE</div>', unsafe_allow_html=True)
            ts_groups = {}
            for entry in st.session_state.timeline:
                ts_groups.setdefault(entry["timestep"], []).append(entry)
            st.markdown("<div style='max-height: 480px; overflow-y: auto; padding-right: 4px;'>", unsafe_allow_html=True)
            for t, entries in sorted(ts_groups.items()):
                for entry in entries:
                    is_success = entry["success"]
                    bg_color = "rgba(255,51,85,0.1)" if is_success else "rgba(0,255,136,0.05)"
                    border_color = "#ff3355" if is_success else "#00ff88"
                    status_text_val = "✓ POTENTIAL PATH" if is_success else "✗ BLOCKED"
                    status_color = "#ff3355" if is_success else "#00ff88"
                    privilege_html = (
                        "<div style='color:#ffd700;font-size:0.65rem'>⬆ Privilege Escalation (simulated)</div>"
                        if entry.get("priv_esc") else ""
                    )
                    vuln_percent = int(entry["vuln"] * 100)
                    criticality_stars = "★" * entry["criticality"]
                    card_html = (
                        f"<div style='background:{bg_color};border:1px solid {border_color};"
                        f"border-left:3px solid {border_color};padding:8px 12px;margin:4px 0;"
                        f"font-family:Share Tech Mono;font-size:0.72rem;line-height:1.8'>"
                        f"<div style='display:flex;justify-content:space-between'>"
                        f"<span style='color:#00d4ff'>T{t}</span>"
                        f"<span style='color:{status_color}'>{status_text_val}</span>"
                        f"</div>"
                        f"<div style='color:#e0f4ff;font-weight:bold'>→ {entry['node']}</div>"
                        f"<div style='color:#3d6a8a'>{entry.get('mitre_code','')}: {entry.get('mitre_desc','')}</div>"
                        f"<div style='color:#ff8c00;font-size:0.65rem'>Reason: {entry.get('access_vector', 'network')}</div>"
                        f"{privilege_html}"
                        f"<div style='color:#7ab8d4'>Risk: {vuln_percent}/100 | Criticality: {criticality_stars}</div>"
                        f"</div>"
                    )
                    st.markdown(card_html, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='background:#0a1520;border:1px solid #1a3a5c;border-left:3px solid #00d4ff;
             padding:24px;font-family:Share Tech Mono;font-size:0.78rem;line-height:2;
             text-align:center;margin-top:16px'>
            <div style='color:#00d4ff;font-size:0.95rem;font-family:Orbitron,monospace;letter-spacing:3px;margin-bottom:12px'>
                READY TO SIMULATE ATTACK
            </div>
            <div style='color:#7ab8d4'>
                1. Select an <b>Attacker Foothold / Entry Point</b> in the controls above.<br>
                2. Click <b>▶ RUN SIMULATION</b> to model lateral movement.<br>
                3. The map above will highlight compromised routes (red/orange) and the timeline will populate below with MITRE ATT&CK techniques.
            </div>
        </div>
        """, unsafe_allow_html=True)

    if st.session_state.simulation_done:
        st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)
        col_log1, col_log2 = st.columns([1, 1], gap="medium")
        with col_log1:
            st.markdown('<div class="section-header">📟 SIMULATED ATTACK EVENT LOG</div>', unsafe_allow_html=True)
            if st.session_state.honeypot_triggered:
                st.markdown("""
                <div class="honeypot-alert">
                    ⚠ HONEYPOT TRIGGERED (SIMULATED) — modeled attacker probed decoy system<br>
                    <span style='color:#3d6a8a'>Action: Risk model updated (+15 penalty)</span>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("""
            <div style='background:#050a0f;border:1px solid #1a3a5c;padding:10px 12px;font-family:Share Tech Mono;max-height:280px;overflow-y:auto'>
            """, unsafe_allow_html=True)
            for log in st.session_state.attack_log:
                sev = log["severity"]
                color = "#ff3355" if sev == "critical" else "#00ff88" if sev == "ok" else "#ff8c00"
                st.markdown(f"""
                <div style='font-size:0.66rem;padding:5px 0;border-bottom:1px solid #0a1520;color:#7ab8d4;line-height:1.6'>
                    <div><span style='color:#3d6a8a'>Source:</span> {log["src"]} &nbsp;→&nbsp; <span style='color:#00d4ff'>Target: {log["target"]}</span></div>
                    <div><span style='color:#3d6a8a'>Technique:</span> {log["technique"]}</div>
                    <div style='color:{color}'>Result: {log["status"]}</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_log2:
            st.markdown('<div class="section-header">🔖 MITRE ATT&CK MAPPING</div>', unsafe_allow_html=True)
            mitre_seen = {}
            for entry in st.session_state.timeline:
                if entry["success"]:
                    mitre_seen[entry["mitre_code"]] = entry["mitre_desc"]
            mitre_html = "".join(f'<span class="mitre-tag">{code}</span>' for code in mitre_seen) + "<br><br>"
            for code, desc in mitre_seen.items():
                mitre_html += f'<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin:3px 0"><span style="color:#ff8c00">{code}</span> — {desc}</div>'
            st.markdown(f'<div style="background:#0d1f2d;border:1px solid #1a3a5c;padding:12px;max-height:280px;overflow-y:auto">{mitre_html}</div>', unsafe_allow_html=True)

# ═════════════════════════════════════════════════════════════════
# TAB 3: 🛡️ DEFENSE & REMEDIATION
# ═════════════════════════════════════════════════════════════════
with tab_defense:
    st.markdown('<div class="section-header">🛡 ACDS DEFENSE OPTIMIZATION &amp; REMEDIATION</div>', unsafe_allow_html=True)
    col_defense, col_solutions = st.columns([1, 1], gap="medium")

    with col_defense:
        st.markdown("""
        <div style='font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;
             background:#060d15;border:1px solid #1a3a5c;padding:10px;margin-bottom:12px;line-height:1.8'>
        // Greedy algorithm: rank by risk_reduction / cost ratio<br>
        // Selects highest-value, CVE-specific actions within budget constraints<br>
        // States: RECOMMENDED → SELECTED → APPLIED TO SIMULATION MODEL
        </div>
        """, unsafe_allow_html=True)

        all_actions_for_budget = get_defense_actions(st.session_state.G, set(st.session_state.G.nodes) - {"Honeypot"}, 50)
        max_budget = sum(a["cost"] for a in all_actions_for_budget) or 100
        st.slider("Defense Budget (units)", 0, max_budget, key="budget",
                   help="Total cost the optimizer can spend selecting recommended controls below.")

        defense_actions = st.session_state.defense_actions
        selected, total_reduction_val, remaining = greedy_defense_selection(defense_actions, st.session_state.budget)
        st.session_state.selected_defenses = selected

        before_risk = st.session_state.risk_before_defense if st.session_state.risk_before_defense is not None else st.session_state.risk_score
        before_bd = st.session_state.blast_before_defense or st.session_state.blast_details

        applied = st.session_state.applied_defenses
        has_applied = bool(applied)

        st.markdown("**RECOMMENDED / SELECTED CONTROLS**")
        selected_set = {a["action"] for a in selected}
        for action in defense_actions[:10]:
            is_sel = action["action"] in selected_set
            card_class = "selected" if is_sel else "unselected"
            badge = DEFENSE_STATE_SELECTED if is_sel else DEFENSE_STATE_RECOMMENDED
            badge_color = "#00ff88" if is_sel else "#3d6a8a"
            type_icons = {
                "patch": "🔧", "isolate": "🔒", "privilege": "👤", "ids": "📡",
                "disable_smb": "🚫", "restrict_rdp": "🖥", "close_port": "🔌",
                "firewall_rule": "🧱", "honeypot_placement": "🍯",
            }
            icon = type_icons.get(action["type"], "⚙")
            priority = action.get("priority", "MEDIUM")
            prio_color = {"HIGH": "#ff3355", "MEDIUM": "#ff8c00", "LOW": "#3d6a8a"}.get(priority, "#3d6a8a")
            mitre_tactic = action.get("mitre_tactic", "")

            st.markdown(f"""
            <div class="defense-action {card_class}">
                <div>
                    <div style='color:#e0f4ff;font-weight:bold'>{icon} {action["action"]}</div>
                    <div style='color:#3d6a8a;font-size:0.68rem;margin-top:3px'>{action["description"]}</div>
                    {f"<div style='color:#7ab8d4;font-size:0.62rem;margin-top:3px'>MITRE: {mitre_tactic}</div>" if mitre_tactic else ""}
                    <div style='margin-top:4px'>
                        <span class='mitre-tag' style='border-color:{prio_color};color:{prio_color}'>{priority} PRIORITY</span>
                        <span class='mitre-tag'>Cost: {action["cost"]}</span>
                        <span class='mitre-tag' style='border-color:#00ff88;color:#00ff88'>-{action["risk_reduction"]} risk</span>
                        <span class='mitre-tag' style='border-color:#00d4ff;color:#00d4ff'>eff: {action["efficiency"]}</span>
                    </div>
                </div>
                <span style='color:{badge_color};font-size:0.62rem;white-space:nowrap'>{badge}</span>
            </div>
            """, unsafe_allow_html=True)

        if st.button("🛡  APPLY SELECTED DEFENSES", use_container_width=True, disabled=not selected):
            applied_actions, ids_dep, seg_applied = apply_defense_actions(st.session_state.G, selected)
            st.session_state.applied_defenses = applied_actions
            st.session_state.ids_deployed = st.session_state.ids_deployed or ids_dep
            st.session_state.segmentation_applied = st.session_state.segmentation_applied or seg_applied

            current_entry = st.session_state.get("last_entry_node") or (entry_node if 'entry_node' in locals() else None)
            live_val_snapshot = st.session_state.get("live_validation_results") or None
            new_timeline, new_compromised, new_honeypot, new_stats = simulate_attack(
                st.session_state.G, current_entry, seed=random.randint(1, 9999),
                ids_deployed=st.session_state.ids_deployed, segmentation_applied=st.session_state.segmentation_applied,
                live_validation=live_val_snapshot,
            )
            new_risk, new_bd = calculate_risk(st.session_state.G, new_compromised, new_timeline, new_honeypot, new_stats)
            st.session_state.timeline = new_timeline
            st.session_state.compromised = new_compromised
            st.session_state.honeypot_triggered = new_honeypot
            st.session_state.attack_stats = new_stats
            st.session_state.risk_score = new_risk
            st.session_state.blast_details = new_bd
            st.session_state.post_defense_stats = new_bd
            st.session_state.mitre_after_defense = {
                e["mitre_code"]: e["mitre_desc"] for e in new_timeline if e["success"]
            }

            if new_honeypot:
                honeypot_engine.record_trigger(
                    source_node=current_entry, decoy_node="Honeypot (decoy)",
                    event_type="simulated_probe_post_defense",
                    details="Simulated attacker reached the decoy node after defenses were applied.",
                    risk_before=new_risk - 15 if new_risk is not None else None,
                    risk_after=new_risk,
                )
            st.session_state.adaptive_feedback = honeypot_engine.apply_adaptive_feedback(new_risk)
            st.session_state.overall_acds_risk = calculate_overall_acds_risk(st.session_state.G, new_risk)
            st.session_state.attack_log = generate_attack_log(new_timeline, new_honeypot)
            record_scan_history(st.session_state.G, "Post-defense")
            st.success(f"Applied {len(applied_actions)} defense action(s) to the simulation model and re-ran the simulation.")
            st.toast(f"🛡 {len(applied_actions)} defense action(s) applied", icon="🛡")
            st.rerun()

    with col_solutions:
        st.markdown('<div class="section-header">💡 RECOMMENDED REMEDIATION (SPECIFIC, PER-HOST)</div>', unsafe_allow_html=True)
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
                'Run an attack simulation to generate targeted remediation steps.</div>',
                unsafe_allow_html=True,
            )

        st.markdown('<br>', unsafe_allow_html=True)
        st.markdown('<div class="section-header">🍯 ADAPTIVE HONEYPOT FEEDBACK</div>', unsafe_allow_html=True)
        af = st.session_state.adaptive_feedback
        if af:
            hp1, hp2, hp3 = st.columns(3)
            hp1.metric("Events (24h)", af["event_count"])
            hp2.metric("Adaptive Boost", f"+{af['boost']}")
            hp3.metric("Adjusted Risk", f"{af['adjusted_risk']}/100", delta=f"{af['boost']}")
            st.markdown(f"""
            <div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;
                 padding:8px 10px;margin:6px 0;background:#1a1000;border-left:3px solid #ffd700">
                {af['reason']}<br>
                <span style="color:#3d6a8a">Method: {af['method']}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No adaptive feedback computed yet — run an attack simulation.</div>', unsafe_allow_html=True)

    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)
    render_before_after_verification()

# ═════════════════════════════════════════════════════════════════
# TAB 4: 🧬 ASSETS & VULNERABILITIES
# ═════════════════════════════════════════════════════════════════
with tab_assets_vulns:
    st.markdown('<div class="section-header">🧬 ASSET INVENTORY &amp; VULNERABILITY INTELLIGENCE</div>', unsafe_allow_html=True)

    # Live Asset Inventory and Changes (if real scan mode)
    if st.session_state.network_mode == "Real Network Scan":
        if st.session_state.monitoring_enabled:
            st.fragment(run_every=st.session_state.monitor_interval)(_render_monitoring_panel)()
        else:
            _render_monitoring_panel()
        st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)

    render_recent_changes_timeline()
    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)

    vuln_col1, vuln_col2 = st.columns([1, 1], gap="medium")

    with vuln_col1:
        st.markdown('<div class="section-header">🦠 ALL CONFIRMED CVEs DISCOVERED ON NETWORK</div>', unsafe_allow_html=True)
        all_cves = []
        for node, data in st.session_state.G.nodes(data=True):
            for c in data.get('cve_findings', []):
                all_cves.append((node, data['ip'], c))
        all_cves.sort(key=lambda x: x[2]['cvss'], reverse=True)
        if all_cves:
            for node, ip, c in all_cves[:12]:
                st.markdown(f"""
                <div style="font-family:Share Tech Mono;font-size:0.66rem;color:#7ab8d4;
                     padding:8px 10px;margin:4px 0;background:#0a1520;border-left:3px solid #ff3355">
                    <span class="cve-tag">{c['cve_id']}</span>
                    <span class="mitre-tag" style="border-color:#ff3355;color:#ff3355">CVSS {c['cvss']} ({c.get('severity','?')})</span>
                    <div style="margin-top:4px;color:#e0f4ff">{node.replace(chr(10),' / ')} ({ip}) — {c['service']} {c.get('detected_version') or ''}</div>
                    <div style="margin-top:2px;color:#3d6a8a">{c['summary'][:120]}{'...' if len(c['summary'])>120 else ''}</div>
                    <div style="margin-top:2px;color:#3d6a8a">Published: {c.get('published')} · Confidence: {c.get('detection_confidence')}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No version-specific CVEs matched (services may be unversioned, patched, or NVD unreachable — '
                'baseline exposure risk was used instead).</div>',
                unsafe_allow_html=True,
            )

    with vuln_col2:
        st.markdown('<div class="section-header">🧬 DEDUPLICATED FINDINGS (unique CVE × affected assets)</div>', unsafe_allow_html=True)
        grouped_findings = vuln_dedup.deduplicate_findings(st.session_state.G)
        if grouped_findings:
            for g in grouped_findings[:15]:
                asset_list = ", ".join(a["display_name"] for a in g["affected_assets"][:6])
                if g["affected_count"] > 6:
                    asset_list += f" (+{g['affected_count'] - 6} more)"
                st.markdown(f"""
                <div style="font-family:Share Tech Mono;font-size:0.66rem;color:#7ab8d4;
                     padding:8px 10px;margin:4px 0;background:#0a1520;border-left:3px solid #00d4ff">
                    <span class="cve-tag">{g['cve_id']}</span>
                    <span class="mitre-tag" style="border-color:#ff3355;color:#ff3355">CVSS {g['cvss']} ({g.get('severity','?')})</span>
                    <span style="color:#ffd700;margin-left:6px">Affected Assets: {g['affected_count']}</span>
                    <div style="margin-top:4px;color:#e0f4ff">{asset_list}</div>
                    <div style="margin-top:2px;color:#3d6a8a">Service: {g['service']} · Source: {g['detection_source']}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No CVE findings to deduplicate yet.</div>', unsafe_allow_html=True)

    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)
    cve_hist_col, change_det_col = st.columns([1, 1], gap="medium")

    with cve_hist_col:
        st.markdown('<div class="section-header">🧬 VULNERABILITY LIFECYCLE TIMELINE</div>', unsafe_allow_html=True)
        _CVE_EVENT_ICON = {"DISCOVERED": "🔴", "RESOLVED": "🟢", "CVSS_CHANGED": "🟡", "VERSION_CHANGED": "🟣"}
        cve_events = st.session_state.get("cve_timeline") or monitor_db.get_cve_timeline(limit=30)
        if not cve_events:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No CVE lifecycle events recorded yet.</div>', unsafe_allow_html=True)
        else:
            for e in cve_events[:20]:
                icon = _CVE_EVENT_ICON.get(e.get("event_type"), "⚪")
                ts = (e.get("timestamp") or "")[:16].replace("T", " ")
                st.markdown(f"""
                <div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;
                     padding:6px 10px;margin:3px 0;background:#0a1520;border-left:3px solid #1a3a5c'>
                    <span style='color:#00d4ff'>{ts}</span>
                    &nbsp;{icon}&nbsp;
                    <span style='color:#e0f4ff'>{html_lib.escape(str(e.get("detail") or ""))}</span>
                </div>
                """, unsafe_allow_html=True)

    with change_det_col:
        st.markdown('<div class="section-header">🔁 CHANGE DETECTION (vs last persisted scan)</div>', unsafe_allow_html=True)
        cs = st.session_state.change_summary
        if not cs:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'Run a Real Network Scan to generate a persisted baseline for comparison.</div>',
                unsafe_allow_html=True)
        elif not cs["has_baseline"]:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'This is the first persisted scan — no previous snapshot to compare against yet. '
                'Future scans will diff against this one.</div>', unsafe_allow_html=True)
        else:
            cd1, cd2, cd3, cd4 = st.columns(4)
            cd1.metric("New", len(cs["new_assets"]))
            cd2.metric("Missing", len(cs["missing_assets"]))
            cd3.metric("New CVEs", len(cs["new_vulnerabilities"]))
            cd4.metric("Fixed", len(cs["resolved_vulnerabilities"]))

            if cs["changed_assets"]:
                for ca in cs["changed_assets"][:6]:
                    field_lines = "".join(
                        f"<div style='color:#3d6a8a'>&bull; {c['field']}: {c['before']} → {c['after']}</div>"
                        for c in ca["changes"]
                    )
                    st.markdown(f"""
                    <div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;
                         padding:8px 10px;margin:4px 0;background:#0a1520;border-left:3px solid #ff8c00">
                        <span style="color:#e0f4ff">{ca['hostname'] or ca['ip']} ({ca['ip']})</span>
                        {f"<span style='color:#ffd700;margin-left:8px'>Risk: {ca['risk_before']} → {ca['risk_after']}</span>" if ca['risk_delta'] is not None else ""}
                        {field_lines}
                    </div>
                    """, unsafe_allow_html=True)
            if not (cs["new_assets"] or cs["missing_assets"] or cs["changed_assets"]):
                st.markdown(
                    '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#00ff88">'
                    'No changes detected since the last scan.</div>', unsafe_allow_html=True)

# ═════════════════════════════════════════════════════════════════
# TAB 5: 🚨 ALERT CENTER, REPORTS & SETTINGS
# ═════════════════════════════════════════════════════════════════
with tab_alerts:
    st.markdown('<div class="section-header">🎯 DEDICATED ALERT CENTER</div>', unsafe_allow_html=True)

    ac_col1, ac_col2, ac_col3 = st.columns([1.3, 2, 1.3])
    with ac_col1:
        ac_severity = st.selectbox("Severity Filter", ["All", "Critical", "High", "Medium", "Low", "Info"],
                                    key="alert_center_severity", help="Show only alerts at this severity level.")
    with ac_col2:
        ac_search = st.text_input("Search by IP, hostname, CVE, or alert type",
                                   key="alert_center_search", placeholder="e.g. 192.168.1.12, CVE-2024-…, RISK_INCREASE",
                                   help="Matches against the asset, title, description, and alert type fields.")
    with ac_col3:
        ac_show_acked = st.checkbox("Show acknowledged alerts", value=False, key="alert_center_show_acked",
                                     help="Acknowledged alerts are hidden by default but never deleted.")

    ac_results = monitor_db.get_alerts(
        limit=300,
        severity=None if ac_severity == "All" else ac_severity.upper(),
        search=ac_search.strip() if ac_search else None,
        acknowledged=None if ac_show_acked else False,
    )

    st.markdown(
        f"<div style='font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;margin-bottom:6px'>"
        f"{len(ac_results)} alert(s) matching current filters</div>", unsafe_allow_html=True)

    if not ac_results:
        st.markdown(
            '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
            'No alerts match these filters.</div>', unsafe_allow_html=True)
    else:
        for a in ac_results[:50]:
            sev = a.get("severity", "INFO")
            color = _ALERT_SEVERITY_COLOR.get(sev, "#3d6a8a")
            icon = _ALERT_TYPE_ICON.get(a.get("alert_type"), "🔔")
            ts = (a.get("timestamp") or "")[:19].replace("T", " ")
            is_acked = bool(a.get("acknowledged"))
            card_col, btn_col = st.columns([5, 1])
            with card_col:
                delta_html = ""
                if a.get("old_value") and a.get("new_value"):
                    delta_html = (f"<div style='color:#e0f4ff;font-family:Orbitron,monospace;font-size:0.75rem;margin-top:3px'>"
                                   f"{html_lib.escape(str(a['old_value']))} → {html_lib.escape(str(a['new_value']))}</div>")
                ack_badge = (f"<span style='color:#00ff88;font-size:0.6rem;margin-left:8px'>✔ ACKNOWLEDGED "
                             f"{(a.get('acknowledged_at') or '')[:16].replace('T',' ')}</span>") if is_acked else ""
                st.markdown(f"""
                <div style='background:#0d1f2d;border:1px solid {color};border-left:4px solid {color};
                     padding:9px 12px;margin:4px 0;font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;
                     opacity:{0.6 if is_acked else 1}'>
                    <div style='display:flex;justify-content:space-between;align-items:center'>
                        <span style='color:{color};font-weight:bold'>{icon} {sev} — {a.get("title","")}</span>
                        <span style='color:#3d6a8a;font-size:0.6rem'>{ts}</span>
                    </div>
                    <div style='color:#e0f4ff;margin-top:2px'>Asset: {html_lib.escape(str(a.get("asset") or "—"))}
                        <span style='color:#3d6a8a'>· {a.get("alert_type","")}</span>{ack_badge}</div>
                    <div style='margin-top:2px'>{html_lib.escape(str(a.get("description") or ""))}</div>
                    {delta_html}
                </div>
                """, unsafe_allow_html=True)
            with btn_col:
                if not is_acked:
                    if st.button("✅ Ack", key=f"ack_alert_{a['id']}", use_container_width=True,
                                 help="Mark this alert acknowledged — it stays in history, never deleted."):
                        monitor_db.acknowledge_alert(a["id"])
                        st.toast("Alert acknowledged", icon="✅")
                        st.rerun()

    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)

    st.markdown('<div class="section-header">📤 EXECUTIVE REPORTING &amp; DATA EXPORT</div>', unsafe_allow_html=True)
    rep1, rep2, rep3, rep4 = st.columns(4)
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
    with rep4:
        if REPORTLAB_AVAILABLE:
            pdf_bytes = build_executive_report_pdf(
                st.session_state.G, st.session_state.risk_score, st.session_state.blast_details, overall,
                st.session_state.scan_history,
                defense_actions=st.session_state.defense_actions,
                applied_defenses=st.session_state.applied_defenses,
                risk_before=st.session_state.risk_before_defense,
                blast_before=st.session_state.blast_before_defense,
                overall_before=st.session_state.overall_acds_risk_before,
                risk_after=st.session_state.risk_score if st.session_state.applied_defenses else None,
                blast_after=st.session_state.post_defense_stats,
                overall_after=overall if st.session_state.applied_defenses else None,
                mitre_before=st.session_state.mitre_before_defense,
                mitre_after=st.session_state.mitre_after_defense,
                alerts=monitor_db.get_alerts(limit=200),
            )
            st.download_button("⬇ Executive Report (PDF)", pdf_bytes or b"",
                                file_name="acds_executive_report.pdf", mime="application/pdf",
                                use_container_width=True, disabled=pdf_bytes is None)
        else:
            st.button("⬇ Executive Report (PDF)", disabled=True, use_container_width=True,
                       help="reportlab is not installed — run: pip install reportlab")

    st.markdown('<hr style="border-color:#1a3a5c;margin:16px 0">', unsafe_allow_html=True)
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

    with st.expander("⚙ SYSTEM SETTINGS", expanded=False):
        _s = monitor_db.get_all_settings()
        st.markdown(
            '<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#3d6a8a;margin-bottom:10px">'
            'Changes are saved to SQLite and take effect immediately for the rest of this session.</div>', unsafe_allow_html=True)

        set_col1, set_col2 = st.columns(2)
        with set_col1:
            st.markdown("**Monitoring**")
            s_interval = st.selectbox("Monitoring Interval", ["30s", "1m", "5m"],
                                       index=["30s", "1m", "5m"].index(_s["monitoring_interval"]),
                                       key="settings_monitor_interval",
                                       help="How often background monitoring re-scans while enabled.")
            s_scan_timeout = st.slider("Scan Timeout (seconds/port)", 0.2, 5.0,
                                        float(_s["scan_timeout_seconds"]), 0.1, key="settings_scan_timeout",
                                        help="Per-port connect timeout during discovery.")
            s_banner_timeout = st.slider("Banner Read Timeout (seconds)", 0.2, 5.0,
                                          float(_s["banner_timeout_seconds"]), 0.1, key="settings_banner_timeout",
                                          help="How long to wait for a service banner before giving up on that port.")
            s_nvd_cache = st.slider("NVD Cache Duration (hours)", 1, 168,
                                     int(_s["nvd_cache_hours"]), 1, key="settings_nvd_cache",
                                     help="How long a CVE lookup result is reused before re-querying NVD.")

        with set_col2:
            st.markdown("**Risk &amp; Alerts**")
            s_crit = st.slider("Risk Threshold — CRITICAL ≥", 50, 100,
                                int(_s["risk_threshold_critical"]), 1, key="settings_risk_critical")
            s_high = st.slider("Risk Threshold — HIGH ≥", 30, int(s_crit) - 1,
                                min(int(_s["risk_threshold_high"]), int(s_crit) - 1), 1, key="settings_risk_high")
            s_medium = st.slider("Risk Threshold — MEDIUM ≥", 0, int(s_high) - 1,
                                  min(int(_s["risk_threshold_medium"]), max(int(s_high) - 1, 0)), 1,
                                  key="settings_risk_medium")
            s_alert_threshold = st.selectbox(
                "Alert Severity Threshold", ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                index=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(_s["alert_severity_threshold"]),
                key="settings_alert_threshold",
                help="Alerts below this severity are not persisted.")
            s_budget = st.number_input("Default Defense Budget", min_value=10, max_value=500,
                                        value=int(_s["default_budget"]), step=10, key="settings_default_budget")
            st.selectbox("Theme", ["cyberpunk"], index=0, key="settings_theme", disabled=True,
                         help="ACDS currently ships one theme; this preference is persisted for future themes.")

    if st.button("💾 SAVE SETTINGS", use_container_width=True):
        new_settings = {
            "monitoring_interval": s_interval,
            "scan_timeout_seconds": s_scan_timeout,
            "banner_timeout_seconds": s_banner_timeout,
            "nvd_cache_hours": s_nvd_cache,
            "risk_threshold_critical": s_crit,
            "risk_threshold_high": s_high,
            "risk_threshold_medium": s_medium,
            "alert_severity_threshold": s_alert_threshold,
            "default_budget": s_budget,
            "theme": "cyberpunk",
        }
        for key, value in new_settings.items():
            monitor_db.set_setting(key, value)
        apply_runtime_settings(monitor_db.get_all_settings())
        st.session_state.monitor_interval = s_interval
        st.session_state.budget = s_budget
        acds_log.info("Settings saved: %s", new_settings)
        st.success("Settings saved and applied.")
        st.toast("⚙ Settings saved", icon="⚙")
        st.rerun()

# ─────────────────────────────────────────────────────────────────
# SPRINT 3 — PHASE 9: ABOUT ACDS
# Every number and formula quoted below is copied verbatim from the
# actual functions that compute it (calculate_risk,
# calculate_overall_acds_risk, core/network_exposure.py) — nothing here
# is a simplified/marketing restatement, so this page stays accurate
# as a demo reference even as the rest of the app evolves.
# ─────────────────────────────────────────────────────────────────
with st.expander("ℹ ABOUT ACDS", expanded=False):
    st.markdown("""
    <div style='font-family:Orbitron,monospace;color:#00d4ff;font-size:1.1rem;letter-spacing:2px'>
        ADAPTIVE CYBER DEFENSE SYSTEM — ACDS v3.0
    </div>
    <div style='font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a;margin-bottom:14px'>
        An SME network defense simulation platform: passive discovery, real CVE matching,
        graph-based exposure modeling, MITRE-aligned attack-path simulation, and an adaptive
        defense optimizer — built for demonstration and training, not production SOC use.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**🏗 Architecture**")
    st.markdown("""
    <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;line-height:1.9;margin-bottom:14px'>
    • <b>app.py</b> — Streamlit UI + orchestration (single entry point: <code>streamlit run app.py</code>)<br>
    • <b>core/database.py</b> — persistent asset inventory, alerts, risk history, settings, CVE cache (SQLite)<br>
    • <b>core/network_exposure.py</b> — Phase 2/3 graph-topology exposure &amp; critical-asset scoring<br>
    • <b>core/alert_engine.py</b> — diff-based alerting (RISK_INCREASE/DECREASE, NEW_CVE, exposure changes)<br>
    • <b>core/change_detector.py</b> — asset/port/service diffing between scans<br>
    • <b>core/vuln_dedup.py</b> — collapses repeated CVE findings into unique CVE × affected-asset groups<br>
    • <b>core/honeypot_engine.py</b> — adaptive honeypot feedback loop<br>
    • <b>core/acds_logging.py</b> — shared rotating-file + console logger<br>
    • <b>data/</b> — SQLite database files live here (<code>acds.db</code>, <code>acds.log</code>)
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**🔍 Passive Scanning**")
    st.markdown("""
    <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;line-height:1.9;margin-bottom:14px'>
    ACDS only ever OBSERVES: ICMP ping sweep, ARP table reads, reverse DNS/NetBIOS name
    resolution, TCP connect-scans against a fixed port list, and reading whatever a service
    hands back when a connection is opened (a "banner"). It never sends exploit payloads,
    brute-forces credentials, or performs any offensive action — this is a hard constraint of
    the tool, not a configurable setting.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**🕸 Network Exposure**")
    st.markdown("""
    <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;line-height:1.9;margin-bottom:14px'>
    Every discovered asset gets a <b>network_exposure</b> risk component, and the
    organization-wide figure is the mean of that component across all non-honeypot assets.
    Separately, <b>Critical Asset Exposure</b> is the percentage of CRITICAL/HIGH-criticality
    assets (criticality level ≥ 4) that are either reachable from another discovered asset on
    the exposure graph or expose at least one open port themselves.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**💥 Blast Radius**")
    st.markdown("""
    <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;line-height:1.9;margin-bottom:14px'>
    Computed only after an attack-path simulation runs, from three weighted factors:<br><br>
    &nbsp;&nbsp;Blast Radius = 0.3 × <i>Spread</i> + 0.5 × <i>Critical Impact</i> + 0.2 × <i>Depth</i><br><br>
    — <b>Spread</b>: fraction of real (non-honeypot) assets compromised<br>
    — <b>Critical Impact</b>: compromised assets' share of total criticality-weighted value<br>
    — <b>Depth</b>: how many simulation timesteps the attack reached, relative to network size<br><br>
    A successful honeypot trigger adds a flat +15 (capped at 100), since triggering a decoy
    signals the attacker took a path a real defender would want flagged regardless of
    "technical" blast radius.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**🎯 Overall ACDS Risk Formula**")
    st.markdown(f"""
    <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;line-height:1.9;margin-bottom:14px'>
    A documented, non-industry-standard aggregation of four independently-computed components:<br><br>
    &nbsp;&nbsp;Overall ACDS Risk =&nbsp;
    Average Asset Risk × {OVERALL_WEIGHT_ASSET_RISK}<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;+ Network Blast Radius × {OVERALL_WEIGHT_BLAST_RADIUS}<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;+ Critical Asset Exposure × {OVERALL_WEIGHT_CRITICAL_EXPOSURE}<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;+ Network Exposure × {OVERALL_WEIGHT_NETWORK_EXPOSURE}<br><br>
    If no attack simulation has been run yet, Blast Radius is unknown — ACDS reports a
    <b>PARTIAL</b> result built from the other three components rather than inventing a number
    for the missing one. Risk Thresholds (the CRITICAL/HIGH/MEDIUM/LOW cutoffs applied to any
    0-100 score) are configurable in ⚙ Settings.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**🔖 MITRE ATT&CK Methodology**")
    st.markdown("""
    <div style='font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;line-height:1.9;margin-bottom:14px'>
    Every step of a simulated attack's lateral movement is tagged with the MITRE ATT&CK
    technique it best represents (e.g. T1021 Remote Services, T1078 Valid Accounts, T1190
    Exploit Public-Facing Application). The Adaptive Defense Optimizer's recommendations each
    carry the specific technique(s) they mitigate, and the Before vs After Verification page
    re-runs the simulation to show which techniques were actually neutralized. All of this is
    <b>SIMULATED — NO REAL ATTACK TRAFFIC</b> is generated at any point.
    </div>
    """, unsafe_allow_html=True)

    st.markdown(
        '<div style="text-align:center;font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;'
        'margin-top:6px;border-top:1px solid #1a3a5c;padding-top:10px">'
        'ACDS v3.0 — for security education, training, and internal SME risk demonstrations.'
        '</div>', unsafe_allow_html=True)


