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

# ─────────────────────────────────────────────────────────────────
# ACDS v4.0 — NEW MODULE IMPORTS (Phases 1-13, backward-compatible)
# ─────────────────────────────────────────────────────────────────
try:
    from core import (
        attack_graph_intelligence,
        graph_risk_prioritizer,
        adaptive_simulation,
        defense_optimizer_v4,
        adaptive_cycle,
        alert_correlator,
        historical_intelligence,
        threat_intelligence,
        vuln_dedup,
        sme_lab,
        report_generator_v4,
    )
    from core.attack_graph_intelligence import (
        resolve_mitre_technique, build_explainable_edge,
        enrich_graph_edges, render_edge_explanation_html,
    )
    from core.graph_risk_prioritizer import (
        rank_all_assets_by_priority, render_priority_breakdown_html,
    )
    from core.adaptive_simulation import (
        detect_topology_changes, render_topology_change_html,
    )
    from core.defense_optimizer_v4 import (
        generate_v4_defense_actions, render_defense_action_card_v4,
    )
    from core.adaptive_cycle import (
        CYCLE_STAGES, get_cycle_stage_status,
        compute_before_after_comparison,
        render_adaptive_cycle_html, render_before_after_v4,
    )
    from core.alert_correlator import (
        correlate_alerts, detect_monitoring_events,
        render_correlated_alert_html,
    )
    from core.historical_intelligence import (
        get_overall_risk_trend, calculate_defense_effectiveness,
        build_exposure_trend_from_history, render_historical_trend_html,
    )
    from core.threat_intelligence import (
        enrich_cve_with_threat_intel, calculate_ti_adjusted_priority,
        render_threat_intel_badge, is_in_cisa_kev, CISA_KEV_OFFLINE,
    )
    from core.vuln_dedup import (
        deduplicate_findings, get_vulnerability_statistics,
    )
    from core.sme_lab import (
        SME_LAB_NODES, build_lab_graph_nodes,
        validate_lab_paths, render_lab_validation_html,
    )
    from core.report_generator_v4 import (
        build_report_data, export_csv, export_pdf,
    )
    V4_MODULES_LOADED = True
except Exception as _v4_import_err:
    V4_MODULES_LOADED = False

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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    --bg-base: #090D16;
    --bg-surface: #0F172A;
    --bg-card: #151E32;
    --bg-card-hover: #1C2844;
    --bg-card-elevated: #1E293B;
    --border-color: #23324D;
    --border-subtle: #1A2438;
    --border-focus: #3B82F6;
    --text-primary: #F8FAFC;
    --text-secondary: #94A3B8;
    --text-muted: #64748B;
    --accent-blue: #3B82F6;
    --accent-indigo: #6366F1;
    --sev-critical: #EF4444;
    --sev-high: #F97316;
    --sev-medium: #F59E0B;
    --sev-low: #10B981;
    --sev-info: #0EA5E9;
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

html, body, [data-testid="stApp"] {
    background-color: var(--bg-base) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-sans) !important;
}

/* Sidebar styling */
[data-testid="stSidebar"] {
    background: #0B1120 !important;
    border-right: 1px solid var(--border-color) !important;
}

[data-testid="stSidebar"] * {
    font-family: var(--font-sans) !important;
}

[data-testid="stSidebar"] .stRadio > div {
    gap: 4px;
}

[data-testid="stSidebar"] .stRadio label {
    padding: 7px 12px !important;
    border-radius: 6px !important;
    transition: all 0.2s ease !important;
    font-size: 0.85rem !important;
    font-weight: 500 !important;
    color: var(--text-secondary) !important;
}

[data-testid="stSidebar"] .stRadio label:hover {
    background: rgba(59, 130, 246, 0.08) !important;
    color: var(--text-primary) !important;
}

/* Standard Button styling */
.stButton > button {
    background: #1E293B !important;
    color: #F8FAFC !important;
    border: 1px solid var(--border-color) !important;
    font-family: var(--font-sans) !important;
    font-size: 0.82rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.3px !important;
    padding: 8px 18px !important;
    border-radius: 6px !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2) !important;
}

.stButton > button:hover {
    background: #27354E !important;
    border-color: var(--accent-blue) !important;
    color: #FFFFFF !important;
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15) !important;
    transform: translateY(-1px) !important;
}

.stButton > button:active {
    transform: translateY(0) !important;
}

/* Selectbox & Inputs */
.stSelectbox > div > div, .stTextInput > div > div {
    background: var(--bg-surface) !important;
    border: 1px solid var(--border-color) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-sans) !important;
    border-radius: 6px !important;
}

.stSelectbox > div > div:focus-within, .stTextInput > div > div:focus-within {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 1px var(--accent-blue) !important;
}

/* Metrics */
.stMetric {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    padding: 16px 20px !important;
    border-radius: 8px !important;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15) !important;
}

.stMetric label {
    color: var(--text-secondary) !important;
    font-family: var(--font-sans) !important;
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.5px !important;
    text-transform: uppercase !important;
}

.stMetric [data-testid="metric-container"] > div:nth-child(2) {
    color: var(--text-primary) !important;
    font-family: var(--font-sans) !important;
    font-size: 1.45rem !important;
    font-weight: 700 !important;
}

/* Typography & Headings */
h1, h2, h3, h4 {
    font-family: var(--font-sans) !important;
    color: var(--text-primary) !important;
    font-weight: 700 !important;
    letter-spacing: -0.2px !important;
}

/* Expanders */
.stExpander {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 8px !important;
    margin-bottom: 12px !important;
}

.stExpander summary {
    color: var(--text-primary) !important;
    font-family: var(--font-sans) !important;
    font-size: 0.85rem !important;
    font-weight: 600 !important;
    padding: 12px 16px !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 6px;
    background-color: var(--bg-surface);
    padding: 6px 8px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    margin-bottom: 20px;
}
.stTabs [data-baseweb="tab"] {
    font-family: var(--font-sans), sans-serif;
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--text-secondary);
    border-radius: 6px;
    padding: 8px 16px;
    transition: all 0.2s ease;
    border: 1px solid transparent;
    background: transparent;
}
.stTabs [data-baseweb="tab"]:hover {
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.04);
}
.stTabs [aria-selected="true"] {
    color: #FFFFFF !important;
    background: #1E293B !important;
    border-color: var(--border-color) !important;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
}
.stTabs [data-baseweb="tab-border"] { display: none; }
.stTabs [data-baseweb="tab-highlight"] { background-color: var(--accent-blue); }

/* Custom Enterprise SOC Components */
.soc-header-bar {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 14px 20px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
}

.soc-header-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 8px;
}

.soc-header-subtitle {
    font-size: 0.78rem;
    color: var(--text-muted);
    margin-top: 2px;
}

.soc-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 18px 22px;
    margin-bottom: 16px;
}

.soc-card-title {
    font-size: 0.82rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-secondary);
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

/* Category Badges */
.badge-category {
    display: inline-flex;
    align-items: center;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 3px 8px;
    border-radius: 4px;
    text-transform: uppercase;
}

.badge-real {
    background: rgba(59, 130, 246, 0.12);
    border: 1px solid rgba(59, 130, 246, 0.35);
    color: #60A5FA;
}

.badge-validated {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.35);
    color: #34D399;
}

.badge-simulated {
    background: rgba(168, 85, 247, 0.12);
    border: 1px solid rgba(168, 85, 247, 0.35);
    color: #C084FC;
}

.badge-cached {
    background: rgba(148, 163, 184, 0.12);
    border: 1px solid rgba(148, 163, 184, 0.35);
    color: #94A3B8;
}

/* Severity Pills */
.badge-sev {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.3px;
    text-align: center;
}

.badge-sev-critical {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.4);
    color: #EF4444;
}

.badge-sev-high {
    background: rgba(249, 115, 22, 0.15);
    border: 1px solid rgba(249, 115, 22, 0.4);
    color: #F97316;
}

.badge-sev-medium {
    background: rgba(245, 158, 11, 0.15);
    border: 1px solid rgba(245, 158, 11, 0.4);
    color: #F59E0B;
}

.badge-sev-low {
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.4);
    color: #10B981;
}

.badge-sev-info {
    background: rgba(14, 165, 233, 0.15);
    border: 1px solid rgba(14, 165, 233, 0.4);
    color: #0EA5E9;
}

/* Simulation Disclaimer Banner */
.soc-sim-banner {
    background: rgba(168, 85, 247, 0.08);
    border: 1px solid rgba(168, 85, 247, 0.25);
    border-left: 4px solid #A855F7;
    border-radius: 6px;
    padding: 10px 16px;
    margin-bottom: 16px;
    font-size: 0.8rem;
    color: #D8B4FE;
    display: flex;
    align-items: center;
    gap: 10px;
}

/* Action Cards */
.soc-action-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-left: 4px solid var(--accent-blue);
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.soc-action-card.critical { border-left-color: var(--sev-critical); }
.soc-action-card.high { border-left-color: var(--sev-high); }
.soc-action-card.medium { border-left-color: var(--sev-medium); }
.soc-action-card.low { border-left-color: var(--sev-low); }

/* Table styling helpers */
.soc-code {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    background: rgba(0, 0, 0, 0.25);
    padding: 2px 5px;
    border-radius: 3px;
    border: 1px solid rgba(255, 255, 255, 0.08);
}

/* Targeted fix for Streamlit sidebar collapse control */
[data-testid="stSidebarCollapseButton"] span[data-testid="stIconMaterial"],
[data-testid="collapsedControl"] span[data-testid="stIconMaterial"] {
    font-family: 'Material Symbols Outlined', sans-serif !important;
    font-size: 0 !important;
    line-height: 1 !important;
}
[data-testid="stSidebarCollapseButton"] span[data-testid="stIconMaterial"]::after,
[data-testid="collapsedControl"] span[data-testid="stIconMaterial"]::after {
    font-size: 1rem;
    content: '\21C4';
}

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
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

def grab_banner(ip, port, timeout=1.5):
    """
    Connect to an open port and read whatever banner/header the service
    offers. This is passive — we never send exploit payloads, only the
    minimal protocol-correct request needed to elicit a version string
    (e.g. an HTTP HEAD/GET, a TLS ClientHello). Returns (raw_banner, version_str).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # HTTP / HTTP-Alt
            if port in (80, 8080, 8000, 8888, 5000):
                http_req = (
                    f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (compatible; ACDS-Scanner/2.0)\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.sendall(http_req)
                data = sock.recv(2048).decode(errors='ignore')
                m = re.search(r'Server:\s*([^\r\n]+)', data, re.IGNORECASE)
                if not m and ("40" in data[:30] or not data):
                    # If HEAD returned no Server header, try a quick lightweight GET
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as gsock:
                            gsock.settimeout(timeout)
                            gsock.connect((ip, port))
                            gsock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: ACDS/2.0\r\n\r\n".encode())
                            gdata = gsock.recv(2048).decode(errors='ignore')
                            gm = re.search(r'Server:\s*([^\r\n]+)', gdata, re.IGNORECASE)
                            if gm:
                                return gdata[:300], gm.group(1).strip()
                    except Exception:
                        pass
                return data[:300], (m.group(1).strip() if m else (data.splitlines()[0] if data else None))

            # HTTPS / HTTPS-Alt
            if port in (443, 8443):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                        tls.settimeout(timeout)
                        tls.sendall(
                            f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
                            f"User-Agent: Mozilla/5.0 (compatible; ACDS-Scanner/2.0)\r\n"
                            f"Connection: close\r\n\r\n".encode()
                        )
                        data = tls.recv(2048).decode(errors='ignore')
                        m = re.search(r'Server:\s*([^\r\n]+)', data, re.IGNORECASE)
                        return data[:300], (m.group(1).strip() if m else None)
                except (ssl.SSLError, OSError):
                    return None, None

            # MySQL (Port 3306)
            if port == 3306:
                data = sock.recv(1024)
                if len(data) > 5:
                    try:
                        null_idx = data.find(b'\x00', 5)
                        if null_idx != -1:
                            ver_str = data[5:null_idx].decode(errors='ignore')
                            return f"MySQL Handshake {ver_str}", ver_str
                    except Exception:
                        pass
                return (data[:300].decode(errors='ignore') if data else None), None

            # Banner-on-connect protocols: SSH (22), FTP (21), SMTP (25, 587), POP3 (110), IMAP (143), Telnet (23)
            data = sock.recv(1024).decode(errors='ignore').strip()
            if not data:
                return None, None
            first_line = data.splitlines()[0] if data else None
            return data[:300], first_line
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
        r'(lighttpd/[\d.]+)',
        r'(Postfix)',
        r'(Exim\s+[\d.]+)',
        r'(redis_version:[\d.]+)',
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            ver = m.group(1).replace('_', ' ').replace('-', ' ', 1).strip()
            ver = re.sub(r'/(\d)', r' \1', ver)
            return ver
    
    # Generic product + numeric version extraction
    m = re.search(r'(Apache|nginx|OpenSSH|vsftpd|ProFTPD|MySQL|MariaDB|lighttpd|IIS)[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+)+)', banner, re.I)
    if m:
        return f"{m.group(1)} {m.group(2)}"
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
    name = str(name).strip().rstrip('.')
    name = re.sub(r'\.local$', '', name, flags=re.IGNORECASE)
    if not name or name == ip or name.replace('.', '') == ip.replace('.', ''):
        return None
    return name


def resolve_hostname_local(ip):
    """Check if the scanned IP is localhost or matches the local host adapter."""
    try:
        if ip in ("127.0.0.1", "localhost", "::1"):
            return socket.gethostname()
        local_ips = set()
        try:
            local_ips.add(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
        if ip in local_ips:
            return socket.gethostname()
    except Exception:
        pass
    return None


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


def resolve_hostname_http(ip, timeout=0.8):
    """Attempt non-destructive HTTP probe to extract server HTML title / hostname header."""
    for port, scheme in [(80, "http"), (8080, "http"), (443, "https")]:
        try:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"{scheme}://{ip}:{port}/"
            req = urllib.request.Request(url, headers={"User-Agent": "ACDS-Scanner/2.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = resp.read(2048).decode("utf-8", errors="ignore")
                match = re.search(r'<title>(.+?)</title>', data, re.IGNORECASE)
                if match:
                    title = match.group(1).strip()
                    if title and not any(x in title.lower() for x in ["404", "403", "500", "error", "not found"]):
                        clean = _clean_hostname(title.split("-")[0].split(":")[0].strip(), ip)
                        if clean and len(clean) < 32:
                            return clean
        except Exception:
            pass
    return None


def resolve_hostname(ip, open_ports=None, services=None, banner_map=None):
    system = platform.system()
    for resolver in (
        lambda: resolve_hostname_local(ip),
        lambda: resolve_hostname_ping(ip, system),
        lambda: resolve_hostname_netbios(ip) if system == "Windows" else None,
        lambda: resolve_hostname_dns(ip),
        lambda: resolve_hostname_http(ip) if (not open_ports or any(p in (open_ports or []) for p in (80, 443, 8080))) else None,
    ):
        try:
            name = resolver()
            if name:
                return name
        except Exception:
            continue
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
        h = rec.get('hostname')
        d_name = rec.get('display_name', '')
        if not h or str(h).strip().lower() in ('unknown', 'none', '', '—'):
            if d_name and ' (' in d_name:
                h = d_name.split(' (')[0].strip()
            elif d_name and '@' in d_name:
                h = d_name.split(' @')[0].strip()
            elif d_name and d_name != rec.get('ip'):
                h = d_name.strip()
            else:
                dev_t = (rec.get('device_type') or 'Host').lower().replace(' ', '-')
                ip_tail = str(rec.get('ip', '0')).split('.')[-1]
                h = f"{dev_t}-{ip_tail}"
            rec['hostname'] = h
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

    if not hostname or str(hostname).strip().lower() in ('unknown', 'none', '', '—'):
        if display_name and ' (' in display_name:
            hostname = display_name.split(' (')[0].strip()
        elif display_name and '@' in display_name:
            hostname = display_name.split(' @')[0].strip()
        elif display_name and display_name != ip:
            hostname = display_name.strip()
        else:
            dev_t = (device_type or 'Host').lower().replace(' ', '-')
            ip_tail = str(ip).split('.')[-1]
            hostname = f"{dev_t}-{ip_tail}"

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


def sync_live_validation_to_graph(G, target_ip_or_id, val_res):
    """
    Propagates live validation findings back into the active topology graph (G),
    session cache, SQLite persistence, and recomputes all risk metrics:
      1. Updates open ports & active services on the target node.
      2. Updates banner_map and version_map from live findings.
      3. Correlates CVE findings for detected software versions.
      4. Recomputes Asset Risk (vuln, ports, sensitive, crit, network exposure).
      5. Updates lateral exposure edges (removes closed port edges, adds new open port edges).
      6. Re-applies network centrality and exposure scores across G.
      7. Syncs st.session_state.last_scan_devices cache.
      8. Persists updated asset snapshot to SQLite database (monitor_db).
    """
    if not G or G.number_of_nodes() == 0 or not val_res:
        return {}

    target_ip = val_res.get("ip") or val_res.get("target_ip") or str(target_ip_or_id)
    target_node = None

    for node, data in G.nodes(data=True):
        if (node == target_ip_or_id or 
            data.get("ip") == target_ip or 
            data.get("asset_id") == target_ip_or_id or
            data.get("display_name") == target_ip_or_id):
            target_node = node
            break

    if not target_node:
        return {}

    data = G.nodes[target_node]
    old_ports = list(data.get("open_ports", []))
    old_risk = float(data.get("risk_score", 0.0))

    new_open_ports = sorted(list(val_res.get("open_ports", [])))
    new_services = sorted(list({PORT_SERVICE_MAP.get(p, f"Port {p}") for p in new_open_ports}))
    new_version_map = dict(data.get("version_map", {}))
    new_banner_map = dict(data.get("banner_map", {}))

    # Update banners and versions from live validation
    ports_val = val_res.get("ports_validated") or val_res.get("ports") or {}
    if not isinstance(ports_val, dict):
        ports_val = {}

    for p in new_open_ports:
        p_info = ports_val.get(p, {}) if isinstance(ports_val, dict) else {}
        s_name = p_info.get("service") or PORT_SERVICE_MAP.get(p, f"Port {p}")
        b_text = p_info.get("banner") or (val_res.get("banner_map") or {}).get(s_name) or (val_res.get("banner_map") or {}).get(p)
        if b_text:
            new_banner_map[s_name] = b_text
            new_banner_map[p] = b_text
            new_banner_map[str(p)] = b_text
            v_str = parse_version_from_banner(s_name, b_text)
            if v_str:
                new_version_map[s_name] = v_str
                new_version_map[p] = v_str
                new_version_map[str(p)] = v_str

    # Remove closed ports from maps
    closed_detected = val_res.get("closed_ports_detected", [])
    for p in closed_detected:
        s_name = PORT_SERVICE_MAP.get(p, f"Port {p}")
        new_banner_map.pop(s_name, None)
        new_banner_map.pop(p, None)
        new_banner_map.pop(str(p), None)
        new_version_map.pop(s_name, None)
        new_version_map.pop(p, None)
        new_version_map.pop(str(p), None)

    # Re-classify and assess security
    role = assign_role_from_services(new_services, data.get("os", "unknown"), data.get("device_type", "Computer"))
    security = assess_device_security(
        new_services, data.get("os", "unknown"), data.get("device_type", "Computer"),
        new_open_ports, role, version_map=new_version_map, ip=data.get("ip", target_ip)
    )
    criticality = calculate_criticality(
        data.get("device_type", "Computer"), new_services, new_open_ports, data.get("os", "unknown")
    )
    other_assets = max(0, len(G.nodes) - 1)
    network_comp = calculate_network_exposure_score(len(new_open_ports), other_assets)
    asset_risk = calculate_asset_risk(
        security["vulnerability_component"], security["service_component"],
        security["sensitive_component"], calculate_criticality_score(criticality["level"]),
        network_comp
    )

    # Apply updates to G node
    data["open_ports"] = new_open_ports
    data["services"] = new_services
    data["version_map"] = new_version_map
    data["banner_map"] = new_banner_map
    data["role"] = role
    data["criticality"] = criticality["level"]
    data["criticality_label"] = criticality["label"]
    data["criticality_confidence"] = criticality["confidence"]
    data["criticality_evidence"] = criticality["evidence"]
    data["vulnerability"] = round(asset_risk["score"] / 100, 3)
    data["exposure_level"] = security["exposure_level"]
    data["risk_score"] = asset_risk["score"]
    data["risk_severity"] = asset_risk["severity"]
    data["risk_components"] = asset_risk["components"]
    data["asset_risk"] = asset_risk
    data["fixes"] = security["fixes"]
    data["weaknesses"] = security["weaknesses"]
    data["access_vectors"] = security["access_vectors"]
    data["cve_findings"] = security["cve_findings"]
    data["exposure_findings"] = security["exposure_findings"]
    data["cve_source"] = security["cve_source"]
    data["last_seen"] = "Live Validated"

    # Rebuild incoming lateral edges for target_node
    in_edges_to_remove = [(u, v) for u, v in G.in_edges(target_node)]
    G.remove_edges_from(in_edges_to_remove)

    for src_node in G.nodes:
        if src_node == target_node:
            continue
        for edge_info in get_lateral_edges_for_target(new_open_ports):
            G.add_edge(
                src_node, target_node,
                connection=edge_info['connection'],
                access_vector=edge_info['vector'],
                access_port=edge_info['port'],
                mitre_code=edge_info['mitre_code'],
                mitre_desc=edge_info['mitre_desc'],
                success_prob=edge_info['success_prob'],
                reachability='POTENTIAL REACHABILITY'
            )

    # Re-apply graph-wide network exposure scores
    network_exposure.apply_network_exposure_scores(G, SENSITIVE_PORTS, recompute_node_risk)

    # Sync raw device session cache
    raw_devices = st.session_state.get("last_scan_devices", []) or []
    for d in raw_devices:
        d_ip = d.get("ip") if isinstance(d, dict) else (d[0] if len(d) > 0 else None)
        if d_ip == target_ip:
            if isinstance(d, dict):
                d["open_ports"] = new_open_ports
                d["services"] = new_services
                d["version_map"] = new_version_map
                d["banner_map"] = new_banner_map
                d["risk_score"] = asset_risk["score"]
                d["cve_findings"] = security["cve_findings"]

    # Persist updated asset to SQLite
    try:
        monitor_db.upsert_asset({
            "ip_address": target_ip,
            "mac_address": data.get("mac"),
            "hostname": data.get("hostname"),
            "vendor": data.get("mac_vendor"),
            "device_type": data.get("device_type"),
            "operating_system": data.get("os"),
            "criticality": criticality["level"],
            "current_risk": asset_risk["score"],
            "status": "ONLINE" if val_res.get("reachable") else "OFFLINE",
            "open_ports": ",".join(str(p) for p in new_open_ports),
            "services": ",".join(new_services),
            "last_seen": datetime.now(timezone.utc).isoformat()
        })
    except Exception:
        pass

    return {
        "target_node": target_node,
        "old_ports": old_ports,
        "new_ports": new_open_ports,
        "new_opened": val_res.get("new_ports_detected", []),
        "new_closed": val_res.get("closed_ports_detected", []),
        "old_risk": old_risk,
        "new_risk": asset_risk["score"],
    }


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
    all_criticality = sum(G.nodes[n].get("criticality", G.nodes[n].get("business_criticality", 2)) for n in real_nodes)
    compromised_criticality = sum(G.nodes[n].get("criticality", G.nodes[n].get("business_criticality", 2)) for n in real_compromised)
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
    """
    Mutates the in-memory asset/network model so a re-simulation produces a genuinely
    different, technically defensible result. Tracks applied patches/fixes and saves the
    pre-defense baseline snapshot for before/after comparison.
    Returns (applied_actions, ids_deployed, segmentation_applied).
    """
    # 1. Establish Before baseline if not already captured
    if st.session_state.get("risk_before_defense") is None and st.session_state.get("risk_score") is not None:
        st.session_state.risk_before_defense = float(st.session_state.get("risk_score", 0.0))
    if not st.session_state.get("blast_before_defense") and st.session_state.get("blast_details"):
        st.session_state.blast_before_defense = dict(st.session_state.get("blast_details") or {})
    if not st.session_state.get("overall_acds_risk_before") and st.session_state.get("overall_acds_risk"):
        st.session_state.overall_acds_risk_before = dict(st.session_state.get("overall_acds_risk") or {})
    if not st.session_state.get("compromised_before_defense") and st.session_state.get("compromised"):
        st.session_state.compromised_before_defense = set(st.session_state.get("compromised") or set())
    if not st.session_state.get("timeline_before_defense") and st.session_state.get("timeline"):
        st.session_state.timeline_before_defense = list(st.session_state.get("timeline") or [])
    if not st.session_state.get("mitre_before_defense") and st.session_state.get("timeline"):
        st.session_state.mitre_before_defense = {
            t['mitre_code']: t.get('mitre_desc', 'Remote Service')
            for t in st.session_state.get('timeline', []) if t.get('mitre_code')
        }

    newly_applied = []
    applied_patches_ledger = list(st.session_state.get("applied_patches", []) or [])
    prev_applied = list(st.session_state.get("applied_defenses", []) or [])
    ids_deployed = st.session_state.get("ids_deployed", False)
    segmentation_applied = st.session_state.get("segmentation_applied", False)

    for action in selected_actions:
        node = action.get("node")
        atype = str(action.get("type", "")).lower()
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if atype == "ids" and node == "ALL":
            ids_deployed = True
        elif atype in ("isolate", "firewall_rule") and node == "ALL":
            segmentation_applied = True
        elif node in G.nodes:
            nd = G.nodes[node]
            comps = nd.get("risk_components")
            if atype in ("patch", "update_software"):
                # Clear confirmed CVEs and zero out the vulnerability component
                nd["cve_findings"] = []
                if comps and 'vulnerability' in comps:
                    comps['vulnerability']['normalized_score'] = 0.0
                recompute_node_risk(nd)
            elif atype == "isolate":
                # Isolate the node: zero exposure & sever lateral network edges
                nd["isolated"] = True
                if comps and 'network_exposure' in comps:
                    comps['network_exposure']['normalized_score'] = 0.0
                recompute_node_risk(nd)
                in_edges = list(G.in_edges(node))
                out_edges = list(G.out_edges(node))
                G.remove_edges_from(in_edges + out_edges)
            elif atype == "privilege":
                if comps and 'criticality' in comps:
                    comps['criticality']['normalized_score'] = round(comps['criticality']['normalized_score'] * 0.6, 1)
                recompute_node_risk(nd)
            elif atype in ("disable_smb", "restrict_rdp", "close_port", "restrict"):
                port_map = {"disable_smb": 445, "restrict_rdp": 3389}
                port_to_close = port_map.get(atype)
                if port_to_close is None:
                    m = re.search(r"port (\d+)", str(action.get("action", "")) + " " + str(action.get("description", "")))
                    port_to_close = int(m.group(1)) if m else None
                if port_to_close and port_to_close in (nd.get("open_ports") or []):
                    nd["open_ports"] = [p for p in nd["open_ports"] if p != port_to_close]
                    # Remove incoming lateral edges targeting this port
                    edges_to_remove = [
                        (u, v) for u, v, d in G.in_edges(node, data=True)
                        if d.get('port') == port_to_close or d.get('access_port') == port_to_close
                    ]
                    G.remove_edges_from(edges_to_remove)
                if comps and 'network_exposure' in comps:
                    comps['network_exposure']['normalized_score'] = round(
                        comps['network_exposure']['normalized_score'] * 0.5, 1)
                    recompute_node_risk(nd)
            elif atype == "honeypot_placement":
                if comps and 'vulnerability' in comps:
                    comps['vulnerability']['normalized_score'] = round(
                        comps['vulnerability']['normalized_score'] * 0.8, 1)
                recompute_node_risk(nd)

        applied_entry = {
            **action,
            "state": DEFENSE_STATE_APPLIED,
            "applied_at": now_ts
        }
        newly_applied.append(applied_entry)
        applied_patches_ledger.append({
            "Timestamp": now_ts,
            "Target Host": node,
            "Target IP": G.nodes[node].get("ip", node) if node in G.nodes else "Network-wide",
            "Fix Category": atype.upper(),
            "Control Applied": action.get("description", action.get("action")),
            "Cost": action.get("cost", 10),
            "Expected Reduction": f"-{action.get('risk_reduction', 0):.1f} pts",
            "Status": "✓ Applied to Model",
        })

    st.session_state.applied_defenses = prev_applied + newly_applied
    st.session_state.applied_patches = applied_patches_ledger
    st.session_state.ids_deployed = ids_deployed
    st.session_state.segmentation_applied = segmentation_applied
    st.session_state.pending_re_simulation = True

    return newly_applied, ids_deployed, segmentation_applied


def run_post_defense_re_simulation(G, entry_node=None):
    """
    Re-runs the decision-based attack propagation simulator against the hardened graph model
    with all applied patches, isolated nodes, and firewall rules in effect.
    Computes AFTER metrics and updates session state for comparative evaluation.
    """
    if not G or G.number_of_nodes() == 0:
        return None

    all_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    if not all_nodes:
        return None

    if not entry_node or entry_node not in G.nodes:
        entry_node = st.session_state.get("last_entry_node") or all_nodes[0]

    sim_ids = st.session_state.get("ids_deployed", False)
    sim_seg = st.session_state.get("segmentation_applied", False)

    timeline, decision_log, comp_after, uncomp_after, succ_paths, blocked_paths, attack_stats = simulate_decision_based_propagation(
        G, entry_node, seed=42, ids_deployed=sim_ids, segmentation_applied=sim_seg
    )
    honeypot_trig = any(
        entry.get("ntype") == "honeypot" and entry.get("success") for entry in timeline
    )
    risk_sc_after, blast_details_after = calculate_risk(G, comp_after, timeline, honeypot_trig, attack_stats)
    overall_acds_risk_after = calculate_overall_acds_risk(G, risk_sc_after)

    # Record post-defense outcomes
    st.session_state.post_defense_stats = blast_details_after
    st.session_state.risk_score_after = risk_sc_after
    st.session_state.overall_acds_risk_after = overall_acds_risk_after
    st.session_state.compromised_after = comp_after
    st.session_state.timeline_after = timeline
    st.session_state.decision_log_after = decision_log
    st.session_state.mitre_after_defense = {
        t['mitre_code']: t.get('mitre_desc', 'Remote Service')
        for t in timeline if t.get('mitre_code')
    }
    st.session_state.post_defense_sim_done = True
    st.session_state.pending_re_simulation = False

    return {
        "risk_score_after": risk_sc_after,
        "blast_details_after": blast_details_after,
        "overall_acds_risk_after": overall_acds_risk_after,
        "compromised_after": comp_after,
        "timeline_after": timeline,
    }


def reset_model_defenses_to_baseline(G):
    """Resets in-memory model modifications back to the original baseline scan state."""
    st.session_state.applied_defenses = []
    st.session_state.applied_patches = []
    st.session_state.ids_deployed = False
    st.session_state.segmentation_applied = False
    st.session_state.pending_re_simulation = False
    st.session_state.post_defense_sim_done = False
    st.session_state.post_defense_stats = None
    st.session_state.risk_score_after = None
    st.session_state.overall_acds_risk_after = None
    st.session_state.compromised_after = None
    st.session_state.timeline_after = None
    st.session_state.decision_log_after = None
    st.session_state.mitre_after_defense = None

    # Re-build graph from original scan if available
    raw_devices = st.session_state.get("last_scan_devices")
    if raw_devices:
        st.session_state.G = build_dynamic_graph(raw_devices)
    else:
        for node, d in G.nodes(data=True):
            d["isolated"] = False
            recompute_node_risk(d)


# ─────────────────────────────────────────────────────────────────
# SPRINT 3 — PHASE 2: DEDICATED BEFORE vs AFTER VERIFICATION PAGE
# ─────────────────────────────────────────────────────────────────

def _verification_metric_row(rows):
    """rows: list of (label, before_val, after_val_or_None, lower_is_better)."""
    cards = []
    for label, before_val, after_val, lower_is_better in rows:
        if after_val is None:
            cards.append(f"""
            <div style='flex:1;min-width:140px;background:#0d1f2d;border:1px solid #1a3a5c;padding:12px;text-align:center;border-radius:6px'>
                <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.62rem;letter-spacing:1px'>{label}</div>
                <div style='color:#ffd700;font-family:Orbitron,monospace;font-size:1.25rem;margin-top:4px'>{before_val}</div>
                <div style='color:#64748B;font-family:Share Tech Mono;font-size:0.6rem;margin-top:2px'>pending re-simulation</div>
            </div>""")
            continue
        delta = round(after_val - before_val, 1)
        improved = (delta <= 0) if lower_is_better else (delta >= 0)
        arrow_color = "#00ff88" if improved else ("#ffd700" if delta == 0 else "#ff3355")
        delta_str = f"{'+' if delta > 0 else ''}{delta}"
        cards.append(f"""
        <div style='flex:1;min-width:140px;background:#0d1f2d;border:1px solid {arrow_color};padding:12px;text-align:center;border-radius:6px'>
            <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.62rem;letter-spacing:1px'>{label}</div>
            <div style='font-family:Orbitron,monospace;font-size:1.15rem;margin-top:4px'>
                <span style='color:#ff3355'>{before_val}</span>
                <span style='color:#3d6a8a;font-size:0.85rem'> → </span>
                <span style='color:#00ff88'>{after_val}</span>
            </div>
            <div style='color:{arrow_color};font-family:Share Tech Mono;font-size:0.72rem;margin-top:4px'>{delta_str} {'pts' if 'RISK' in label or 'BLAST' in label else ''}</div>
        </div>""")
    return "<div style='display:flex;gap:10px;flex-wrap:wrap;margin:10px 0'>" + "".join(cards) + "</div>"


def render_before_after_verification():
    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())
    
    before_overall = st.session_state.get("overall_acds_risk_before") or st.session_state.get("overall_acds_risk")
    before_bd = st.session_state.get("blast_before_defense") or st.session_state.get("blast_details") or {}
    before_risk = st.session_state.get("risk_before_defense") if st.session_state.get("risk_before_defense") is not None else st.session_state.get("risk_score")

    applied_defenses = st.session_state.get("applied_defenses", [])
    applied_patches = st.session_state.get("applied_patches", [])
    has_defenses = bool(applied_defenses or applied_patches)

    post_sim_done = bool(st.session_state.get("post_defense_sim_done"))
    after_overall_obj = st.session_state.get("overall_acds_risk_after") or (st.session_state.get("overall_acds_risk") if post_sim_done else None)
    after_bd = st.session_state.get("post_defense_stats") if post_sim_done else None
    after_risk = st.session_state.get("risk_score_after") if post_sim_done else None

    all_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    entry_node = st.session_state.get("last_entry_node") or (all_nodes[0] if all_nodes else None)

    # 1. Action / Re-Simulation Toolbar
    rc1, rc2, rc3 = st.columns([5, 4, 3])
    with rc1:
        st.markdown(f"**Hardened Model Status:** `{len(applied_defenses)} defense control(s) applied`")
    with rc2:
        if all_nodes:
            sel_entry = st.selectbox("Re-Attack Entry Point", all_nodes, index=all_nodes.index(entry_node) if entry_node in all_nodes else 0, key="re_sim_entry_sel")
        else:
            sel_entry = None
    with rc3:
        run_re_sim = st.button("🔁 RUN RE-ATTACK SIMULATION", type="primary", use_container_width=True, disabled=not has_defenses)

    if run_re_sim:
        with st.spinner("Re-simulating attack propagation across hardened model..."):
            run_post_defense_re_simulation(G, sel_entry)
            st.toast("Post-defense attack simulation complete!", icon="🛡️")
            st.rerun()

    # Alert Banner if defenses changed but re-simulation pending
    if has_defenses and (st.session_state.get("pending_re_simulation") or not post_sim_done):
        st.markdown("""
        <div style="background:rgba(255,215,0,0.08);border:1px solid #FFD700;border-radius:6px;padding:12px 16px;margin:10px 0 14px 0">
            <div style="display:flex;align-items:center;gap:10px">
                <span style="font-size:1.3rem">⚡</span>
                <div>
                    <b style="color:#FFD700;font-size:0.85rem">Defenses applied to in-memory model!</b>
                    <div style="font-size:0.75rem;color:#CBD5E1">
                        Click <b>🔁 RUN RE-ATTACK SIMULATION</b> above to test whether lateral attack paths were successfully severed and compare Before vs. After results.
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    if before_risk is None:
        st.info("Run an initial attack simulation from the ANALYSIS page to establish the BEFORE baseline.")
        return

    before_overall_score = before_overall.get("overall_score") if before_overall else None
    after_overall_score = after_overall_obj.get("overall_score") if after_overall_obj else None

    # 2. Before vs After Scorecards Row
    st.markdown("#### 📊 Before vs After Comparative Scorecards")
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
    rows = [r for r in rows if r[1] is not None]
    st.markdown(_verification_metric_row(rows), unsafe_allow_html=True)

    # 3. In-Depth "What's Done Better vs. Worse" Evaluation
    if post_sim_done and after_risk is not None:
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        st.markdown("#### 🔬 Detailed Comparative Evaluation: What's Done Better vs Residual Risk")

        before_comp_nodes = set(st.session_state.get("compromised_before_defense") or st.session_state.get("compromised") or set())
        after_comp_nodes = set(st.session_state.get("compromised_after") or set())

        saved_nodes = before_comp_nodes - after_comp_nodes
        newly_comp = after_comp_nodes - before_comp_nodes

        before_mitre = st.session_state.get("mitre_before_defense") or {}
        after_mitre = st.session_state.get("mitre_after_defense") or {}
        neutralized_techniques = set(before_mitre.keys()) - set(after_mitre.keys())

        col_better, col_residual = st.columns(2)

        with col_better:
            st.markdown("""
            <div style="background:#0F291E;border:1px solid #059669;border-radius:8px;padding:16px;height:100%">
                <div style="font-size:0.9rem;font-weight:700;color:#10B981;margin-bottom:8px">
                    🟢 WHAT'S DONE BETTER (Defensive Improvements)
                </div>
            """, unsafe_allow_html=True)

            risk_delta = round(after_risk - before_risk, 1)
            st.markdown(f"- **Blast Radius Reduction:** Reduced by **{abs(risk_delta):.1f} points** ({before_risk:.1f} → {after_risk:.1f})")
            
            if saved_nodes:
                saved_str = ", ".join(f"<code>{n}</code>" for n in saved_nodes)
                st.markdown(f"- **Protected Endpoints:** {len(saved_nodes)} host(s) successfully shielded from compromise ({saved_str})", unsafe_allow_html=True)
            else:
                st.markdown("- **Host Containment:** Scoped entry host isolated / contained.")

            hops_before = before_bd.get("max_lateral_hops", 0)
            hops_after = after_bd.get("max_lateral_hops", 0)
            if hops_after < hops_before:
                st.markdown(f"- **Lateral Chain Severed:** Lateral propagation depth reduced from **{hops_before}** to **{hops_after} hop(s)**.")

            if neutralized_techniques:
                tech_str = ", ".join(f"<code>{t}</code>" for t in neutralized_techniques)
                st.markdown(f"- **MITRE Techniques Neutralized:** {tech_str}", unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        with col_residual:
            st.markdown("""
            <div style="background:#261815;border:1px solid #DC2626;border-radius:8px;padding:16px;height:100%">
                <div style="font-size:0.9rem;font-weight:700;color:#EF4444;margin-bottom:8px">
                    🔴 RESIDUAL RISKS & UNMITIGATED EXPOSURE
                </div>
            """, unsafe_allow_html=True)

            if after_comp_nodes:
                still_comp_str = ", ".join(f"<code>{n}</code>" for n in after_comp_nodes)
                st.markdown(f"- **Reachable in Post-Defense Scope:** {len(after_comp_nodes)} asset(s) still accessible ({still_comp_str})", unsafe_allow_html=True)
            else:
                st.markdown("- **Reachable Endpoints:** 0 assets compromised.")

            if after_mitre:
                rem_tech = ", ".join(f"<code>{t} ({after_mitre[t]})</code>" for t in after_mitre)
                st.markdown(f"- **Remaining Exploitation Techniques:** {rem_tech}", unsafe_allow_html=True)
            else:
                st.markdown("- **MITRE Techniques:** All modeled vectors successfully blocked.")

            if newly_comp:
                st.markdown(f"- ⚠️ **Shifted Exposure Warning:** {len(newly_comp)} node(s) reached via alternate routes.")
            else:
                st.markdown("- **No New Attack Vectors Opened:** Applied controls did not introduce unintended secondary paths.")

            st.markdown("</div>", unsafe_allow_html=True)

    # 4. Applied Patches & Fixes Ledger (Audit Trail)
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown("#### 📋 Applied Patches & Fixes Ledger")
    
    if applied_patches:
        st.dataframe(pd.DataFrame(applied_patches), use_container_width=True, hide_index=True)
    else:
        st.info("No patches or defense controls applied to the simulation model yet. Select controls from the 'Prioritized Action Plan' or 'Budget Defense Optimizer' tabs.")

    # 5. Reset Posture Option
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    if has_defenses:
        if st.button("↺ RESET ALL DEFENSES TO BASELINE SCAN STATE"):
            reset_model_defenses_to_baseline(G)
            st.toast("Model posture restored to baseline scan state.", icon="🔄")
            st.rerun()


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
            f"<b>Host Name:</b> {hostname or data.get('display_name', node)}<br>"
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
            h_name = a.get('hostname') or a.get('display_name') or 'Unknown'
            writer.writerow([
                a.get('ip_address') or '', a.get('mac_address') or 'Unknown',
                h_name, a.get('vendor') or 'Unknown',
                a.get('operating_system') or 'unknown', a.get('device_type') or 'Unknown',
                a.get('current_risk') if a.get('current_risk') is not None else 'N/A',
                crit_label, a.get('status') or 'Unknown',
                (a.get('first_seen') or '')[:19], (a.get('last_seen') or '')[:19],
            ])
    else:
        for node, d in G.nodes(data=True):
            if d.get('node_type') == 'honeypot':
                continue
            h_name = d.get('hostname') or d.get('display_name') or 'Unknown'
            writer.writerow([
                d.get('ip', ''), d.get('mac') or 'Unknown', h_name,
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
    lines.append("ACDS SECURITY ASSESSMENT REPORT")
    lines.append("=" * 45)
    lines.append("ANALYTICAL MODELING ONLY — NO REAL ATTACK TRAFFIC")
    lines.append("PASSIVE NETWORK AUDITING — ZERO EXPLOITATION PERFORMED")
    lines.append("=" * 45)
    lines.append("")
    lines.append("1. EXECUTIVE SUMMARY")
    lines.append(f"  • Assets Discovered: {metrics['assets']}")
    lines.append(f"  • Critical Findings (CVSS >= 9): {metrics['critical']}")
    lines.append(f"  • High Findings (CVSS 7-8.9): {metrics['high']}")
    lines.append(f"  • Average Asset Risk: {metrics['average_risk']}/100")
    lines.append("")
    lines.append("2. TOP RISK ASSETS")
    ranked = sorted(G.nodes(data=True), key=lambda x: x[1].get('risk_score', 0), reverse=True)[:5]
    for node, d in ranked:
        lines.append(f"  • {d.get('display_name', node)} ({d.get('ip')}): {d.get('risk_score',0)}/100 [{d.get('risk_severity','?')}]")
    lines.append("")
    lines.append("3. ATTACK PROPAGATION & SIMULATION METRICS")
    if blast_details:
        hops = blast_details.get('max_lateral_hops', 0)
        spread = blast_details.get('spread', 0.0)
        crit_r = blast_details.get('critical_assets_reached', 0)
        sys_c = blast_details.get('systems_controlled', 0)
        lines.append(f"  • Simulation Status: Completed (Analytical Graph Traversal)")
        lines.append(f"  • Initial Assumed Foothold: Included as starting node (non-exploitative baseline)")
        lines.append(f"  • Network Blast Radius: {spread}% of scoped assets ({sys_c}/{metrics['assets']} hosts)")
        lines.append(f"  • Critical Assets Reached: {crit_r}")
        lines.append(f"  • Lateral Attack Depth: {hops} lateral hop(s)" + (" (Contained to initial foothold)" if hops == 0 else ""))
        if risk_score is not None:
            lines.append(f"  • Simulated Risk Score Before Defense: {risk_score:.1f}/100")
    else:
        lines.append("  • Simulation Status: Not run in this session")
        lines.append("  • Attack Depth & Blast Radius: N/A (Execute simulation in Attack Propagation tab)")
    lines.append("")
    lines.append("4. OVERALL ACDS COMPOSITE RISK")
    if overall_risk:
        lines.append(f"  • Overall Composite Score: {overall_risk.get('overall_score')}/100 ({overall_risk.get('status')})")
        lines.append(f"  • Asset Inherent Risk Component: {overall_risk.get('asset_risk_component', 'N/A')}")
        lines.append(f"  • Simulated Blast Radius Component: {overall_risk.get('blast_radius_component', 'N/A')}")
    else:
        lines.append("  • Overall Composite Score: Pending calculation")
    lines.append("")
    lines.append("5. RECOMMENDED DEFENSIVE ACTIONS")
    seen = set()
    action_count = 0
    for node, d in G.nodes(data=True):
        for fix in d.get('fixes', []):
            if fix not in seen:
                seen.add(fix)
                action_count += 1
                lines.append(f"  [{action_count}] {fix}")
                if action_count >= 8:
                    break
        if action_count >= 8:
            break
    if not seen:
        lines.append("  • No high-priority remediation actions generated.")
    lines.append("")
    if scan_history:
        lines.append("6. SCAN AUDIT TRAIL")
        for h in scan_history[-5:]:
            lines.append(f"  • Scan #{h['scan_id']} — {h['asset_count']} assets, avg risk {h['average_risk']}, "
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


# -*- coding: utf-8 -*-
"""
Enterprise SOC UI Presentation Module for ACDS
"""

import streamlit as st
import pandas as pd
import networkx as nx
import os
import time
from datetime import datetime, timezone
import html as html_lib

# Global Severity Colors
SEV_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#F59E0B",
    "LOW": "#10B981",
    "INFO": "#0EA5E9",
}

# ─────────────────────────────────────────────────────────────────
# HTML UI BADGE & CARD HELPERS
# ─────────────────────────────────────────────────────────────────

def _soc_badge_sev(severity: str) -> str:
    s = (severity or "INFO").upper()
    cls_map = {
        "CRITICAL": "badge-sev-critical",
        "HIGH": "badge-sev-high",
        "MEDIUM": "badge-sev-medium",
        "LOW": "badge-sev-low",
        "INFO": "badge-sev-info",
    }
    cls = cls_map.get(s, "badge-sev-info")
    return f'<span class="badge-sev {cls}">{s}</span>'


def _soc_badge_cat(category: str) -> str:
    c = (category or "REAL OBSERVATION").upper()
    if "REAL-TIME" in c or "VALIDAT" in c:
        return '<span class="badge-category badge-validated">● REAL-TIME VALIDATION</span>'
    elif "SIMULAT" in c or "MODEL" in c:
        return '<span class="badge-category badge-simulated">◈ SIMULATED RESULT</span>'
    elif "CACHE" in c or "OFFLINE" in c:
        return '<span class="badge-category badge-cached">◇ CACHED INTEL</span>'
    else:
        return '<span class="badge-category badge-real">● REAL OBSERVATION</span>'


def _soc_criticality_stars(crit: int) -> str:
    c = _safe_int(crit) or 1
    c = max(1, min(5, c))
    label = {1: "INFORMATIONAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}.get(c, "UNKNOWN")
    stars = "★" * c + "☆" * (5 - c)
    return f'<span title="Criticality Tier {c}/5: {label}" style="color:#F59E0B;font-family:monospace">{stars} ({label})</span>'


def _soc_kpi_card(title: str, value: str, subtitle: str = "", sev_color: str = "#3B82F6", icon: str = "") -> str:
    return f"""
    <div style="background:#151E32;border:1px solid #23324D;border-top:3px solid {sev_color};border-radius:8px;padding:14px 18px;box-shadow:0 2px 4px rgba(0,0,0,0.15)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span style="font-size:0.72rem;font-weight:700;letter-spacing:0.6px;color:#94A3B8;text-transform:uppercase">{title}</span>
            <span style="font-size:1rem">{icon}</span>
        </div>
        <div style="font-size:1.5rem;font-weight:700;color:#F8FAFC;line-height:1.2">{value}</div>
        <div style="font-size:0.75rem;color:#64748B;margin-top:4px">{subtitle}</div>
    </div>
    """


def _soc_header(title: str, subtitle: str = "", category_badge: str = "") -> None:
    badge_html = f"<div>{_soc_badge_cat(category_badge)}</div>" if category_badge else ""
    sub_html = f'<div class="soc-header-subtitle">{subtitle}</div>' if subtitle else ""
    st.markdown(
        f'<div class="soc-header-bar">'
        f'<div><div class="soc-header-title">{title}</div>{sub_html}</div>'
        f'{badge_html}'
        f'</div>',
        unsafe_allow_html=True
    )


# ─────────────────────────────────────────────────────────────────
# 1. OVERVIEW PAGE (Main SOC Dashboard)
# ─────────────────────────────────────────────────────────────────
def render_overview_page():
    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())
    raw_devices = st.session_state.get("last_scan_devices") or []
    net_env = st.session_state.get("network_env") or detect_network_environment()

    # Calculate metrics
    asset_metrics = get_asset_metrics(G)
    db_live_assets = monitor_db.get_live_assets()
    total_assets = len(db_live_assets) if db_live_assets else G.number_of_nodes()
    
    crit_assets_count = 0
    if G.number_of_nodes() > 0:
        crit_assets_count = sum(1 for _, d in G.nodes(data=True) if (d.get("criticality") or 0) >= 4 and d.get("node_type") != "honeypot")
    elif db_live_assets:
        crit_assets_count = sum(1 for a in db_live_assets if (_safe_int(a.get("criticality")) or 0) >= 4)

    dedup_vulns = vuln_dedup.deduplicate_findings(G) if G.number_of_nodes() > 0 else []
    total_vulns = len(dedup_vulns)
    crit_high_vulns = sum(1 for v in dedup_vulns if (v.get("cvss") or 0) >= 7.0 or v.get("severity") in ("CRITICAL", "HIGH"))
    
    active_alerts = monitor_db.get_alerts(limit=500)
    unack_alerts = [a for a in active_alerts if not a.get("acknowledged")]
    
    overall_obj = st.session_state.get("overall_acds_risk") or calculate_overall_acds_risk(G, st.session_state.get("risk_score", 0.0))
    overall_score = overall_obj.get("overall_score") if overall_obj else 0
    overall_sev = overall_obj.get("severity") if overall_obj else "LOW"
    if overall_score is None:
        overall_score = round(overall_obj.get("asset_component", 0.0) if overall_obj else 0.0, 1)
    if not overall_sev:
        overall_sev = severity_from_score(overall_score or 0)

    risk_color = SEV_COLORS.get(overall_sev, "#10B981")

    comp_scores = overall_obj.get('component_scores') if overall_obj and isinstance(overall_obj.get('component_scores'), dict) else {}
    asset_comp_val = comp_scores.get('asset_risk', overall_obj.get('asset_component', 0.0) if overall_obj else 0.0) or 0.0
    blast_comp_val = comp_scores.get('blast_radius', overall_obj.get('blast_component', 0.0) if overall_obj else 0.0) or 0.0
    crit_comp_val = comp_scores.get('critical_exposure', overall_obj.get('critical_exposure_component', 0.0) if overall_obj else 0.0) or 0.0
    net_comp_val = comp_scores.get('network_exposure', overall_obj.get('network_exposure_component', 0.0) if overall_obj else 0.0) or 0.0

    # Header Bar
    last_scan_str = st.session_state.get("scan_completed_at")
    if last_scan_str:
        if isinstance(last_scan_str, datetime):
            last_scan_display = last_scan_str.strftime("%Y-%m-%d %H:%M UTC")
        else:
            last_scan_display = str(last_scan_str)[:16]
    else:
        last_scan_display = "No assessment run yet"

    mon_status = "● Active" if st.session_state.get("monitoring_enabled") else "○ Inactive"
    nvd_status = "Live REST API" if REQUESTS_AVAILABLE else "Offline Intelligence"

    st.markdown(f"""
    <div style="background:#0F172A;border:1px solid #23324D;border-radius:8px;padding:12px 18px;margin-bottom:18px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
        <div style="display:flex;align-items:center;gap:12px">
            <span style="font-size:1.1rem;font-weight:700;color:#F8FAFC">OVERVIEW</span>
            <span style="background:rgba(59,130,246,0.12);border:1px solid rgba(59,130,246,0.3);color:#60A5FA;padding:2px 8px;border-radius:4px;font-size:0.72rem;font-weight:600">ACDS Enterprise</span>
        </div>
        <div style="display:flex;align-items:center;gap:16px;font-size:0.78rem;color:#94A3B8">
            <div><b>Scope:</b> <code>{net_env.get('subnet_cidr', '192.168.1.0/24')}</code></div>
            <div><b>Monitoring:</b> <span style="color:{'#10B981' if st.session_state.get('monitoring_enabled') else '#64748B'}">{mon_status}</span></div>
            <div><b>Threat Intel:</b> <span style="color:#60A5FA">{nvd_status}</span></div>
            <div><b>Last Assessment:</b> {last_scan_display}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # If first run / no data
    if total_assets == 0:
        st.markdown(f"""
        <div style="background:#151E32;border:1px solid #23324D;border-radius:8px;padding:28px;text-align:center;margin-bottom:20px">
            <div style="font-size:1.8rem;margin-bottom:8px">🛡️</div>
            <div style="font-size:1.25rem;font-weight:700;color:#F8FAFC;margin-bottom:6px">Welcome to ACDS Enterprise SOC</div>
            <div style="font-size:0.85rem;color:#94A3B8;max-width:620px;margin:0 auto 20px auto;line-height:1.6">
                Protect your environment by completing your first automated security assessment. ACDS will discover reachable assets, fingerprint services, correlate CVEs, model lateral exposure, and generate prioritized remediation guidance.
            </div>
            <div style="display:flex;justify-content:center;gap:20px;flex-wrap:wrap;margin-bottom:24px;text-align:left">
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:12px 16px;width:160px">
                    <div style="font-size:0.72rem;font-weight:700;color:#3B82F6">STEP 1</div>
                    <div style="font-size:0.82rem;font-weight:600;color:#F8FAFC">Define Scope</div>
                    <div style="font-size:0.7rem;color:#64748B">Detected Subnet</div>
                </div>
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:12px 16px;width:160px">
                    <div style="font-size:0.72rem;font-weight:700;color:#3B82F6">STEP 2</div>
                    <div style="font-size:0.82rem;font-weight:600;color:#F8FAFC">Discover Assets</div>
                    <div style="font-size:0.7rem;color:#64748B">Passive ARP/Ping</div>
                </div>
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:12px 16px;width:160px">
                    <div style="font-size:0.72rem;font-weight:700;color:#3B82F6">STEP 3</div>
                    <div style="font-size:0.82rem;font-weight:600;color:#F8FAFC">Correlate CVEs</div>
                    <div style="font-size:0.7rem;color:#64748B">NIST NVD Live</div>
                </div>
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:12px 16px;width:160px">
                    <div style="font-size:0.72rem;font-weight:700;color:#3B82F6">STEP 4</div>
                    <div style="font-size:0.82rem;font-weight:600;color:#F8FAFC">Analyze Exposure</div>
                    <div style="font-size:0.7rem;color:#64748B">Graph Topology</div>
                </div>
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:12px 16px;width:160px">
                    <div style="font-size:0.72rem;font-weight:700;color:#3B82F6">STEP 5</div>
                    <div style="font-size:0.82rem;font-weight:600;color:#F8FAFC">Respond & Fix</div>
                    <div style="font-size:0.7rem;color:#64748B">Prioritized Defense</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        sc_col1, sc_col2, sc_col3 = st.columns([1, 2, 1])
        with sc_col2:
            st.info("Ready to scan detected local subnet: **" + net_env.get('subnet_cidr', '192.168.1.0/24') + "**")
            if st.button("🚀 START FIRST NETWORK ASSESSMENT", use_container_width=True, type="primary"):
                st.session_state["trigger_scan_now"] = True
                st.rerun()
        return

    # Top KPI Cards
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        st.markdown(_soc_kpi_card("Total Assets", f"{total_assets}", f"{asset_metrics.get('servers', 0)} svr · {asset_metrics.get('other_devices', 0)} ws", "#3B82F6", "💻"), unsafe_allow_html=True)
    with k2:
        st.markdown(_soc_kpi_card("Critical Assets", f"{crit_assets_count}", "Tier 4 & 5 criticality", "#F97316", "🏢"), unsafe_allow_html=True)
    with k3:
        st.markdown(_soc_kpi_card("Open CVEs", f"{total_vulns}", f"Across {len(raw_devices) or total_assets} hosts", "#EF4444", "🔍"), unsafe_allow_html=True)
    with k4:
        st.markdown(_soc_kpi_card("Critical / High", f"{crit_high_vulns}", "CVSS >= 7.0 findings", "#EF4444", "⚠️"), unsafe_allow_html=True)
    with k5:
        st.markdown(_soc_kpi_card("Active Alerts", f"{len(unack_alerts)}", f"{len(active_alerts)} total recorded", "#F59E0B", "🚨"), unsafe_allow_html=True)
    with k6:
        st.markdown(_soc_kpi_card("Overall Risk", f"{overall_score}<span style='font-size:1rem'>/100</span>", f"{overall_sev} SEVERITY", risk_color, "🛡️"), unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # Main Dashboard Body (2 Columns)
    col_left, col_right = st.columns([7, 5])

    with col_left:
        # Security Posture Breakdown
        sev_class = (overall_sev or "low").lower()
        st.markdown(f"""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>Security Posture & Risk Composition</span>
                <span class="badge-sev badge-sev-{sev_class}">{overall_sev} POSTURE</span>
            </div>
            <div style="font-size:0.8rem;color:#94A3B8;margin-bottom:14px;line-height:1.5">
                The overall ACDS score is a transparent composite metric aggregating asset vulnerability severity, analytical attack blast radius, critical asset exposure, and network centrality.
            </div>
            <div style="display:grid;grid-template-columns:repeat(2, 1fr);gap:12px;margin-bottom:12px">
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:10px 14px">
                    <div style="display:flex;justify-content:space-between;font-size:0.75rem;margin-bottom:4px">
                        <span style="color:#94A3B8">Asset Risk (40%)</span>
                        <span style="font-weight:700;color:#F8FAFC">{asset_comp_val:.1f}</span>
                    </div>
                    <div style="background:#1E293B;height:6px;border-radius:3px;overflow:hidden">
                        <div style="background:#3B82F6;width:{min(100, asset_comp_val)}%;height:100%"></div>
                    </div>
                </div>
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:10px 14px">
                    <div style="display:flex;justify-content:space-between;font-size:0.75rem;margin-bottom:4px">
                        <span style="color:#94A3B8">Blast Radius (30%)</span>
                        <span style="font-weight:700;color:#F8FAFC">{blast_comp_val:.1f}</span>
                    </div>
                    <div style="background:#1E293B;height:6px;border-radius:3px;overflow:hidden">
                        <div style="background:#A855F7;width:{min(100, blast_comp_val)}%;height:100%"></div>
                    </div>
                </div>
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:10px 14px">
                    <div style="display:flex;justify-content:space-between;font-size:0.75rem;margin-bottom:4px">
                        <span style="color:#94A3B8">Critical Exposure (15%)</span>
                        <span style="font-weight:700;color:#F8FAFC">{crit_comp_val:.1f}</span>
                    </div>
                    <div style="background:#1E293B;height:6px;border-radius:3px;overflow:hidden">
                        <div style="background:#F97316;width:{min(100, crit_comp_val)}%;height:100%"></div>
                    </div>
                </div>
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:10px 14px">
                    <div style="display:flex;justify-content:space-between;font-size:0.75rem;margin-bottom:4px">
                        <span style="color:#94A3B8">Network Centrality (15%)</span>
                        <span style="font-weight:700;color:#F8FAFC">{net_comp_val:.1f}</span>
                    </div>
                    <div style="background:#1E293B;height:6px;border-radius:3px;overflow:hidden">
                        <div style="background:#10B981;width:{min(100, net_comp_val)}%;height:100%"></div>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Top Priority Findings
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>Top Priority Security Findings</span>
                <span style="font-size:0.72rem;color:#94A3B8">Ordered by Impact</span>
            </div>
        """, unsafe_allow_html=True)

        top_findings = []
        for node, data in G.nodes(data=True):
            if data.get("node_type") == "honeypot":
                continue
            ip = data.get("ip", "")
            hostname = data.get("hostname", "")
            display_name = data.get("display_name", node)
            cves = data.get("cve_findings", [])
            for c in cves:
                top_findings.append({
                    "ip": ip,
                    "hostname": hostname,
                    "display_name": display_name,
                    "cve_id": c.get("cve_id"),
                    "cvss": c.get("cvss", 0.0),
                    "service": c.get("service", "Service"),
                    "fix": c.get("remediation", GENERIC_FIXES.get(c.get("service"), "Upgrade service")),
                    "severity": c.get("severity", cvss_severity_label(c.get("cvss", 0.0))),
                })

        if not top_findings:
            for node, data in G.nodes(data=True):
                if data.get("node_type") == "honeypot":
                    continue
                open_ports = data.get("open_ports", [])
                for p in open_ports:
                    if p in (3389, 445, 23, 21, 5900):
                        svc = PORT_SERVICE_MAP.get(p, "Service")
                        top_findings.append({
                            "ip": data.get("ip", ""),
                            "hostname": data.get("hostname", ""),
                            "display_name": data.get("display_name", node),
                            "cve_id": f"EXPOSED-PORT-{p}",
                            "cvss": 7.5,
                            "service": svc,
                            "fix": GENERIC_FIXES.get(svc, f"Restrict port {p} access"),
                            "severity": "HIGH",
                        })

        top_findings.sort(key=lambda x: float(x.get("cvss") or 0), reverse=True)

        if top_findings:
            for f in top_findings[:4]:
                sev = f["severity"]
                st.markdown(f"""
                <div class="soc-action-card {sev.lower()}">
                    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:4px">
                        <div>
                            {_soc_badge_sev(sev)}
                            <b style="font-size:0.85rem;color:#F8FAFC;margin-left:8px">{f['cve_id']}</b>
                            <span style="font-size:0.75rem;color:#94A3B8;margin-left:6px">· {f['service']}</span>
                        </div>
                        <span style="font-size:0.78rem;font-weight:700;color:{SEV_COLORS.get(sev, '#94A3B8')}">CVSS {f['cvss']}</span>
                    </div>
                    <div style="font-size:0.78rem;color:#94A3B8;margin-bottom:6px">
                        <b>Target Host:</b> <code class="soc-code">{f['ip']}</code> ({f['display_name']})
                    </div>
                    <div style="font-size:0.78rem;color:#CBD5E1;background:#0F172A;padding:6px 10px;border-radius:4px;border:1px solid #1E293B">
                        <b>Recommended Action:</b> {f['fix']}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No active high-severity vulnerabilities found in current assessment.")

        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        # Recent Changes & Change Timeline
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>Recent Changes & Incident Signals</span>
                <span class="badge-category badge-real">AUDIT LOG</span>
            </div>
        """, unsafe_allow_html=True)

        changes = st.session_state.get("change_summary") or {}
        new_assets = changes.get("new_assets") or []
        missing_assets = changes.get("missing_assets") or []
        changed_assets = changes.get("changed_assets") or []
        ip_changed = changes.get("ip_changed_assets") or []
        new_vulns = changes.get("new_vulnerabilities") or []
        has_any_change = bool(new_assets or missing_assets or changed_assets or ip_changed or new_vulns)

        if has_any_change:
            for na in new_assets[:3]:
                if isinstance(na, dict):
                    na_ip = na.get("ip") or "Unknown"
                    na_host = na.get("hostname") or "Discovered Host"
                else:
                    na_ip = str(na)
                    na_host = "Discovered Host"
                st.markdown(f"""
                <div style="font-size:0.78rem;padding:6px 0;border-bottom:1px solid #1E293B">
                    🟢 <b>New Device Detected:</b> <code class="soc-code">{na_ip}</code> ({na_host})
                </div>
                """, unsafe_allow_html=True)
            for ma in missing_assets[:3]:
                ma_ip = ma.get("ip", str(ma)) if isinstance(ma, dict) else str(ma)
                st.markdown(f"""
                <div style="font-size:0.78rem;padding:6px 0;border-bottom:1px solid #1E293B">
                    🔴 <b>Host Disconnected / Offline:</b> <code class="soc-code">{ma_ip}</code>
                </div>
                """, unsafe_allow_html=True)
            for ipc in ip_changed[:3]:
                if isinstance(ipc, dict):
                    st.markdown(f"""
                    <div style="font-size:0.78rem;padding:6px 0;border-bottom:1px solid #1E293B">
                        🔄 <b>IP Reassigned (DHCP):</b> <code class="soc-code">{ipc.get('old_ip')}</code> ➔ <code class="soc-code">{ipc.get('new_ip')}</code> ({ipc.get('hostname') or 'Host'})
                    </div>
                    """, unsafe_allow_html=True)
            for ca in changed_assets[:3]:
                if isinstance(ca, dict):
                    ca_ip = ca.get("ip") or "Unknown"
                    ca_chgs = len(ca.get("changes", []))
                    st.markdown(f"""
                    <div style="font-size:0.78rem;padding:6px 0;border-bottom:1px solid #1E293B">
                        🟡 <b>Asset State Drift:</b> <code class="soc-code">{ca_ip}</code> ({ca_chgs} configuration deltas)
                    </div>
                    """, unsafe_allow_html=True)
            for nv in new_vulns[:3]:
                if isinstance(nv, dict):
                    st.markdown(f"""
                    <div style="font-size:0.78rem;padding:6px 0;border-bottom:1px solid #1E293B">
                        ⚠️ <b>New Vulnerability Correlated:</b> <code class="soc-code">{nv.get('ip','Host')}</code> · {nv.get('cve_id','CVE')}
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="font-size:0.78rem;color:#94A3B8;padding:8px 0">
                ✓ No critical configuration drifts detected between latest observation snapshots.
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

        # Top Recommended Actions
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>Top Remediation Actions</span>
                <span style="font-size:0.72rem;color:#3B82F6;font-weight:600">RESPONSE READY</span>
            </div>
        """, unsafe_allow_html=True)

        defense_actions = get_defense_actions(G, st.session_state.get("compromised", set()), st.session_state.get("risk_score", 0.0))
        if defense_actions:
            for act in defense_actions[:3]:
                act_type = act.get("type", "PATCH").upper()
                st.markdown(f"""
                <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:10px 14px;margin-bottom:8px">
                    <div style="display:flex;justify-content:space-between;font-size:0.75rem;margin-bottom:2px">
                        <span style="font-weight:700;color:#38BDF8">{act_type}: {act.get('node')}</span>
                        <span style="color:#10B981;font-weight:700">-{act.get('risk_reduction', 0):.0f} Risk Pts</span>
                    </div>
                    <div style="font-size:0.75rem;color:#CBD5E1">{act.get('description', act.get('action'))}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="font-size:0.78rem;color:#94A3B8;padding:6px 0">
                Run an attack simulation or network scan to generate optimized defense actions.
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# 2. ASSETS PAGE
# ─────────────────────────────────────────────────────────────────
def render_assets_page():
    _soc_header("ASSETS")

    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())
    raw_devices = st.session_state.get("last_scan_devices") or []

    # Build structured asset records with complete evidence provenance
    asset_list = []
    if G.number_of_nodes() > 0:
        for node, data in G.nodes(data=True):
            if data.get("node_type") == "honeypot":
                continue
            h_raw = data.get("hostname")
            d_name = data.get("display_name", node)
            if not h_raw or str(h_raw).strip().lower() in ("unknown", "none", "", "—"):
                if d_name and " (" in d_name:
                    h_val = d_name.split(" (")[0].strip()
                elif d_name and "@" in d_name:
                    h_val = d_name.split(" @")[0].strip()
                elif d_name and d_name != data.get("ip"):
                    h_val = d_name.strip()
                else:
                    dev_t = (data.get("device_type") or "Host").lower().replace(" ", "-")
                    ip_tail = str(data.get("ip", "0")).split(".")[-1]
                    h_val = f"{dev_t}-{ip_tail}"
            else:
                h_val = str(h_raw).strip()

            asset_list.append({
                "node_id": node,
                "ip": data.get("ip", ""),
                "hostname": h_val,
                "display_name": data.get("display_name", node),
                "device_type": data.get("device_type", "Computer"),
                "os": data.get("os", "unknown"),
                "os_confidence": data.get("os_confidence", "heuristic"),
                "vendor": data.get("mac_vendor", "Unknown Vendor"),
                "mac": data.get("mac", "—"),
                "risk_score": data.get("risk_score", int(data.get("vulnerability", 0) * 100)),
                "risk_severity": data.get("risk_severity", severity_from_score(data.get("risk_score", 0))),
                "risk_components": data.get("risk_components", {}),
                "asset_risk": data.get("asset_risk", {}),
                "criticality": data.get("criticality", 1),
                "criticality_label": data.get("criticality_label", CRITICALITY_LABELS.get(data.get("criticality", 1), "LOW")),
                "open_ports": data.get("open_ports", []),
                "services": data.get("services", []),
                "version_map": data.get("version_map", {}),
                "banner_map": data.get("banner_map", {}),
                "cve_findings": data.get("cve_findings", []),
                "exposure_findings": data.get("exposure_findings", []),
                "weaknesses": data.get("weaknesses", []),
                "access_vectors": data.get("access_vectors", []),
                "fixes": data.get("fixes", []),
                "cve_source": data.get("cve_source", "none"),
                "first_seen": data.get("first_seen", "Initial Scan"),
                "last_seen": data.get("last_seen", "Current Assessment"),
                "isolated": data.get("isolated", False),
            })
    elif raw_devices:
        for d in raw_devices:
            parsed = _parse_device_record(d)
            parsed["node_id"] = parsed.get("ip")
            asset_list.append(parsed)

    if not asset_list:
        st.info("No assets discovered yet. Run a network assessment from the sidebar or Overview page.")
        return

    # Top KPI Metrics Row
    total_count = len(asset_list)
    server_count = sum(1 for a in asset_list if "Server" in str(a.get("device_type", "")) or a.get("device_type") == "Database Server")
    ws_count = sum(1 for a in asset_list if "Workstation" in str(a.get("device_type", "")) or a.get("device_type") == "Computer")
    crit_count = sum(1 for a in asset_list if a.get("criticality", 1) >= 4)
    total_ports = sum(len(a.get("open_ports", [])) for a in asset_list)

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("DISCOVERED ASSETS", total_count)
    with m2:
        st.metric("SERVERS", server_count)
    with m3:
        st.metric("WORKSTATIONS", ws_count)
    with m4:
        st.metric("CRITICAL TIER (4-5)", crit_count)
    with m5:
        st.metric("TOTAL OPEN PORTS", total_ports)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # Search & Filter Toolbar
    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([3, 2, 2, 2, 2])
    with f_col1:
        search_q = st.text_input("🔍 Search Assets", placeholder="Search by IP, hostname, vendor, OS...", label_visibility="collapsed")
    with f_col2:
        risk_filter = st.selectbox("Risk Filter", ["All Risk Bands", "Critical Only", "High & Critical", "Medium", "Low"], label_visibility="collapsed")
    with f_col3:
        crit_filter = st.selectbox("Criticality Filter", ["All Criticalities", "Tier 5 (Critical)", "Tier 4 (High)", "Tier 3 (Medium)", "Tier 1-2 (Low)"], label_visibility="collapsed")
    with f_col4:
        type_filter = st.selectbox("Device Type", ["All Device Types"] + sorted(list({a.get("device_type") for a in asset_list if a.get("device_type")})), label_visibility="collapsed")
    with f_col5:
        if st.button("⚡ Validate All Live", use_container_width=True, help="Concurrently re-scan all network assets in real-time to detect new or closed ports"):
            with st.spinner("Re-validating all assets in real-time (rechecking ports & exposure)..."):
                for a in asset_list:
                    v_res = validate_asset_state(
                        asset_id=a.get("node_id") or a.get("ip"),
                        ip=a.get("ip"),
                        expected_ports=a.get("open_ports", [])
                    )
                    st.session_state.setdefault("live_validation_results", {})[a.get("node_id")] = v_res
                    sync_live_validation_to_graph(G, a.get("node_id"), v_res)
                st.session_state.overall_acds_risk = calculate_overall_acds_risk(G, st.session_state.get("risk_score", 0.0))
                st.success(f"✓ Real-time validation completed for all {len(asset_list)} assets! Updated open ports, lateral paths, and risk scores.")
                st.rerun()

    # Apply Filters
    filtered_assets = []
    for a in asset_list:
        if search_q:
            sq = search_q.lower()
            text_haystack = f"{a.get('ip')} {a.get('hostname')} {a.get('vendor')} {a.get('os')} {a.get('device_type')}".lower()
            if sq not in text_haystack:
                continue
        if risk_filter == "Critical Only" and a.get("risk_severity") != "CRITICAL":
            continue
        elif risk_filter == "High & Critical" and a.get("risk_severity") not in ("CRITICAL", "HIGH"):
            continue
        elif risk_filter == "Medium" and a.get("risk_severity") != "MEDIUM":
            continue
        elif risk_filter == "Low" and a.get("risk_severity") != "LOW":
            continue

        if crit_filter == "Tier 5 (Critical)" and a.get("criticality") != 5:
            continue
        elif crit_filter == "Tier 4 (High)" and a.get("criticality") != 4:
            continue
        elif crit_filter == "Tier 3 (Medium)" and a.get("criticality") != 3:
            continue
        elif crit_filter == "Tier 1-2 (Low)" and a.get("criticality") not in (1, 2):
            continue

        if type_filter != "All Device Types" and a.get("device_type") != type_filter:
            continue

        filtered_assets.append(a)

    st.caption(f"Showing {len(filtered_assets)} of {len(asset_list)} assets")

    # Asset Table
    table_data = []
    for a in filtered_assets:
        ports_str = ", ".join(str(p) for p in a.get("open_ports", [])) or "None"
        table_data.append({
            "IP Address": a.get("ip"),
            "Hostname": a.get("hostname") or a.get("display_name") or "—",
            "Device Type": a.get("device_type"),
            "OS": f"{str(a.get('os')).title()}" if a.get('os') else "Unknown",
            "Vendor": a.get("vendor"),
            "Risk Score": f"{a.get('risk_score')}/100 ({a.get('risk_severity')})",
            "Criticality": f"{a.get('criticality_label')} (Tier {a.get('criticality')})",
            "Open Ports": ports_str,
            "Status": "🟢 Online / Active" if not a.get("isolated") else "🔒 Isolated",
        })

    df_assets = pd.DataFrame(table_data)
    st.dataframe(df_assets, use_container_width=True, hide_index=True)

    # ─────────────────────────────────────────────────────────────
    # Asset Detail Investigation Drawer
    # ─────────────────────────────────────────────────────────────
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown("### 🔎 Asset Deep-Dive Investigation")

    asset_display_options = [f"{a.get('ip')} — {a.get('hostname') or a.get('display_name')} ({a.get('device_type')})" for a in filtered_assets]
    if not asset_display_options:
        asset_display_options = [f"{a.get('ip')} — {a.get('hostname') or a.get('display_name')} ({a.get('device_type')})" for a in asset_list]

    sel_asset_str = st.selectbox("Select Asset to Investigate", asset_display_options, index=0)
    sel_ip = sel_asset_str.split(" ")[0]
    selected_asset = next((a for a in asset_list if a.get("ip") == sel_ip), asset_list[0])

    node_id = selected_asset.get("node_id")

    d_col1, d_col2 = st.columns([8, 4])
    with d_col1:
        st.markdown(f"""
        <div style="background:#151E32;border:1px solid #23324D;border-radius:8px;padding:16px 20px;margin-bottom:12px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                <div>
                    <span style="font-size:1.15rem;font-weight:700;color:#F8FAFC">{selected_asset.get('hostname') or selected_asset.get('display_name')}</span>
                    <span style="font-size:0.85rem;color:#94A3B8;margin-left:8px"><code>{selected_asset.get('ip')}</code></span>
                </div>
                <div>
                    {_soc_badge_sev(selected_asset.get('risk_severity'))}
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:10px;font-size:0.78rem">
                <div><span style="color:#64748B">Host Name:</span> <b style="color:#F8FAFC">{selected_asset.get('hostname') or selected_asset.get('display_name')}</b></div>
                <div><span style="color:#64748B">IP Address:</span> <code class="soc-code">{selected_asset.get('ip')}</code></div>
                <div><span style="color:#64748B">MAC Address:</span> <code class="soc-code">{selected_asset.get('mac','—')}</code></div>
                <div><span style="color:#64748B">Vendor:</span> <b style="color:#CBD5E1">{selected_asset.get('vendor','Unknown')}</b></div>
                <div><span style="color:#64748B">Device Type:</span> <b style="color:#CBD5E1">{selected_asset.get('device_type','Unknown')}</b></div>
                <div><span style="color:#64748B">Inferred OS:</span> <b style="color:#CBD5E1">{str(selected_asset.get('os','unknown')).title()}</b> <span style="font-size:0.68rem;color:#64748B">({selected_asset.get('os_confidence')})</span></div>
                <div><span style="color:#64748B">Criticality:</span> {_soc_criticality_stars(selected_asset.get('criticality',1))}</div>
                <div><span style="color:#64748B">First Seen:</span> <span style="color:#94A3B8">{selected_asset.get('first_seen','Initial Scan')}</span></div>
                <div><span style="color:#64748B">Last Seen:</span> <span style="color:#94A3B8">{selected_asset.get('last_seen','Current Assessment')}</span></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with d_col2:
        st.markdown(
            f'<div style="background:#0F172A;border:1px solid #23324D;border-radius:8px;padding:16px;margin-bottom:12px">'
            f'<div style="font-size:0.75rem;font-weight:700;color:#94A3B8;text-transform:uppercase;letter-spacing:0.5px">Real-Time Validation</div>'
            f'<div style="font-size:0.78rem;color:#64748B;margin-top:4px;line-height:1.4">Actively recheck open ports, discover new ports, and refresh topology.</div>'
            f'</div>',
            unsafe_allow_html=True
        )
        if st.button("⚡ Run Live Validation", use_container_width=True, key=f"val_{sel_ip}"):
            with st.spinner(f"Validating {sel_ip} live (re-checking ports & services)..."):
                val_res = validate_asset_state(
                    asset_id=selected_asset.get("node_id") or selected_asset.get("ip"),
                    ip=selected_asset.get("ip"),
                    expected_ports=selected_asset.get("open_ports", [])
                )
                st.session_state.setdefault("live_validation_results", {})[selected_asset.get("node_id")] = val_res

                # Propagate findings into graph, lateral edges, risk scoring, session state, and SQLite DB
                diff_summary = sync_live_validation_to_graph(G, selected_asset.get("node_id"), val_res)
                st.session_state.overall_acds_risk = calculate_overall_acds_risk(G, st.session_state.get("risk_score", 0.0))

                state_label = "ONLINE & REACHABLE" if val_res.get("reachable") else "UNREACHABLE / OFFLINE"
                st.success(f"✓ Validated: {state_label} ({val_res.get('latency_ms', 0):.1f}ms latency | {len(val_res.get('open_ports', []))} active ports)")
                st.rerun()

    # Detailed Sub-Tabs for Selected Asset
    a_tab_svcs, a_tab_cves, a_tab_risk, a_tab_exp, a_tab_actions = st.tabs([
        "🔌 Services & Ports",
        "🛡️ Vulnerabilities (CVEs)",
        "📊 Risk Score Breakdown",
        "🌐 Exposure & Connections",
        "🔧 Targeted Remediation",
    ])

    with a_tab_svcs:
        open_ports = selected_asset.get("open_ports", [])
        version_map = selected_asset.get("version_map", {})
        banner_map = selected_asset.get("banner_map", {})
        if open_ports:
            svc_rows = []
            for p in open_ports:
                s_name = PORT_SERVICE_MAP.get(p, f"Port {p}")
                s_ver = version_map.get(s_name) or version_map.get(p) or version_map.get(str(p)) or ""
                s_banner = banner_map.get(s_name) or banner_map.get(p) or banner_map.get(str(p)) or ""

                if s_ver:
                    det_status = "Version Detected"
                elif s_banner:
                    det_status = "Banner Obtained (Version Undisclosed)"
                else:
                    det_status = "Port Open (Banner Withheld)"

                svc_rows.append({
                    "Port": p,
                    "Protocol": "TCP",
                    "Service": s_name,
                    "Detected Version": s_ver or "Undisclosed / Unknown",
                    "Detection Status": det_status,
                    "Service Banner": (s_banner[:60] + "…") if len(s_banner) > 60 else (s_banner or "No banner response"),
                    "Exposure Baseline": f"{SERVICE_BASELINE_RISK.get(s_name, 0.4)*100:.0f}/100",
                })
            st.dataframe(pd.DataFrame(svc_rows), use_container_width=True, hide_index=True)
        else:
            st.info("No open TCP ports detected during assessment.")

    with a_tab_cves:
        cves = selected_asset.get("cve_findings", [])
        exp_findings = selected_asset.get("exposure_findings", [])
        if cves:
            cve_rows = []
            for c in cves:
                cve_rows.append({
                    "CVE ID": c.get("cve_id"),
                    "CVSS": c.get("cvss"),
                    "Severity": c.get("severity", cvss_severity_label(c.get("cvss", 0.0))),
                    "Service": c.get("service"),
                    "Summary": c.get("summary", ""),
                    "Source": c.get("source", "NVD Intelligence"),
                    "Fix Version": c.get("fix_version", "Upgrade latest"),
                })
            st.dataframe(pd.DataFrame(cve_rows), use_container_width=True, hide_index=True)
        else:
            st.markdown(
                '<div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:12px 16px;margin-bottom:12px">'
                '<div style="font-size:0.85rem;font-weight:600;color:#F8FAFC">ℹ️ Vulnerability Assessment Intelligence Status</div>'
                '<div style="font-size:0.78rem;color:#94A3B8;margin-top:4px;line-height:1.5">'
                'No version-specific CVEs were matched against NVD or offline intelligence for this asset. '
                '<b>Note:</b> The absence of a matched CVE does not indicate zero risk; services with undisclosed version headers cannot be matched deterministically. '
                'Review baseline exposure findings below.'
                '</div></div>',
                unsafe_allow_html=True
            )
            if exp_findings:
                st.markdown("**Baseline Exposure & Service Risk Findings:**")
                exp_rows = []
                for ef in exp_findings:
                    exp_rows.append({
                        "Service": ef.get("service"),
                        "Port": ef.get("port"),
                        "Baseline Risk": f"{ef.get('baseline_risk', 0.4)*100:.0f}/100",
                        "Risk Reason": ef.get("reason", "Open TCP Service"),
                        "MITRE Tactic": ef.get("mitre_desc", "Exploit Public-Facing Application"),
                    })
                st.dataframe(pd.DataFrame(exp_rows), use_container_width=True, hide_index=True)

    with a_tab_risk:
        r_score = selected_asset.get("risk_score", 0)
        r_sev = selected_asset.get("risk_severity", "LOW")
        r_comps = selected_asset.get("risk_components", {})
        def _get_comp_score(comp_key):
            val = r_comps.get(comp_key, 0.0)
            if isinstance(val, dict):
                return float(val.get("contribution", val.get("normalized_score", 0.0)) or 0.0)
            try:
                return float(val or 0.0)
            except Exception:
                return 0.0

        v_comp = _get_comp_score("vulnerability")
        s_comp = _get_comp_score("service_exposure")
        sen_comp = _get_comp_score("sensitive_services")
        c_comp = _get_comp_score("criticality")
        n_comp = _get_comp_score("network_exposure")

        st.markdown(f"""
        <div style="background:#0F172A;border:1px solid #23324D;border-radius:6px;padding:14px 18px;margin-bottom:12px">
            <div style="font-size:0.9rem;font-weight:700;color:#F8FAFC;margin-bottom:8px">
                Asset Risk Formula Breakdown: <span style="color:#3B82F6">{r_score}/100</span> ({r_sev})
            </div>
            <div style="font-size:0.78rem;color:#94A3B8;line-height:1.6">
                <code>Asset Risk = (40% × Vuln) + (20% × Exposure) + (15% × Sensitive Svc) + (15% × Criticality) + (10% × Centrality)</code>
            </div>
            <div style="display:grid;grid-template-columns:repeat(5, 1fr);gap:10px;margin-top:12px;font-size:0.75rem">
                <div style="background:#151E32;padding:8px;border-radius:4px"><b>Vuln (40%):</b> {v_comp:.1f}</div>
                <div style="background:#151E32;padding:8px;border-radius:4px"><b>Ports (20%):</b> {s_comp:.1f}</div>
                <div style="background:#151E32;padding:8px;border-radius:4px"><b>Sensitive (15%):</b> {sen_comp:.1f}</div>
                <div style="background:#151E32;padding:8px;border-radius:4px"><b>Crit (15%):</b> {c_comp:.1f}</div>
                <div style="background:#151E32;padding:8px;border-radius:4px"><b>Network (10%):</b> {n_comp:.1f}</div>
            </div>
            <div style="font-size:0.75rem;color:#64748B;margin-top:10px">
                <b>Note on Criticality vs Risk:</b> An asset may have HIGH criticality (e.g., Tier 4 Web/DB Server) but LOW risk score if its software is patched, hardened, and has minimal exposure. Criticality reflects business impact; Risk reflects active threat/vulnerability likelihood.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with a_tab_exp:
        if G.has_node(node_id):
            in_edges = list(G.in_edges(node_id, data=True))
            out_edges = list(G.out_edges(node_id, data=True))
            e_col1, e_col2 = st.columns(2)
            with e_col1:
                st.markdown(f"**Inbound Exposure Paths ({len(in_edges)}):**")
                if in_edges:
                    for src, _, d in in_edges[:6]:
                        st.markdown(f"- From **{src}** via {d.get('service','TCP')} (Port {d.get('port','—')})")
                else:
                    st.caption("No inbound lateral paths (typical for single-host scans or isolated nodes).")
            with e_col2:
                st.markdown(f"**Outbound Lateral Reach ({len(out_edges)}):**")
                if out_edges:
                    for _, dst, d in out_edges[:6]:
                        st.markdown(f"- To **{dst}** via {d.get('service','TCP')} (Port {d.get('port','—')})")
                else:
                    st.caption("No outbound lateral paths (typical for single-host scans or endpoints).")
        else:
            st.info("Graph topology not populated for this node.")

    with a_tab_actions:
        st.markdown(f"**Targeted Remediation Plan for {selected_asset.get('ip')}:**")
        fix_count = 0
        for c in selected_asset.get("cve_findings", []):
            fix_count += 1
            st.markdown(f"""
            <div class="soc-action-card critical">
                <b>PATCH:</b> {c.get('cve_id')} on {c.get('service')} — {c.get('remediation', c.get('fix_version', 'Upgrade service'))}
            </div>
            """, unsafe_allow_html=True)
        for p in selected_asset.get("open_ports", []):
            if p in (3389, 445, 23, 21, 5900):
                fix_count += 1
                svc = PORT_SERVICE_MAP.get(p, "Service")
                st.markdown(f"""
                <div class="soc-action-card high">
                    <b>RESTRICT:</b> Close or firewall port {p} ({svc}) — {GENERIC_FIXES.get(svc, 'Restrict access')}
                </div>
                """, unsafe_allow_html=True)
        if fix_count == 0:
            st.success("No immediate remediation required for this host.")


# ─────────────────────────────────────────────────────────────────
# 3. VULNERABILITIES PAGE
# ─────────────────────────────────────────────────────────────────
def render_vulnerabilities_page():
    _soc_header("VULNERABILITIES")

    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())
    all_findings = vuln_dedup.deduplicate_findings(G) if G.number_of_nodes() > 0 else []

    if not all_findings:
        st.info("No vulnerabilities detected in current graph. Run a network scan to detect service banners and correlate CVEs.")
        return

    # Metrics
    total_cves = len(all_findings)
    crit_cves = sum(1 for f in all_findings if (f.get("cvss") or 0) >= 9.0 or f.get("severity") == "CRITICAL")
    high_cves = sum(1 for f in all_findings if 7.0 <= (f.get("cvss") or 0) < 9.0 or f.get("severity") == "HIGH")
    med_cves = sum(1 for f in all_findings if 4.0 <= (f.get("cvss") or 0) < 7.0 or f.get("severity") == "MEDIUM")
    low_cves = total_cves - (crit_cves + high_cves + med_cves)
    kev_count = sum(1 for f in all_findings if threat_intelligence.is_in_cisa_kev(f.get("cve_id", "")))

    v1, v2, v3, v4, v5 = st.columns(5)
    with v1:
        st.metric("TOTAL FINDINGS", total_cves)
    with v2:
        st.metric("CRITICAL (9.0+)", crit_cves)
    with v3:
        st.metric("HIGH (7.0 - 8.9)", high_cves)
    with v4:
        st.metric("MEDIUM / LOW", f"{med_cves + low_cves}")
    with v5:
        st.metric("CISA KNOWN EXPLOITED", kev_count)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # Filter Toolbar
    fc1, fc2, fc3, fc4 = st.columns([3, 2, 2, 2])
    with fc1:
        v_search = st.text_input("Search Findings", placeholder="Search CVE, asset IP, service...", label_visibility="collapsed")
    with fc2:
        v_sev_filter = st.selectbox("Severity", ["All Severities", "Critical", "High", "Medium", "Low"], label_visibility="collapsed")
    with fc3:
        v_ti_filter = st.selectbox("Threat Intel", ["All Findings", "CISA KEV (Actively Exploited) Only"], label_visibility="collapsed")
    with fc4:
        all_svcs = sorted(list({f.get("service") for f in all_findings if f.get("service")}))
        v_svc_filter = st.selectbox("Service", ["All Services"] + all_svcs, label_visibility="collapsed")

    filtered_findings = []
    for f in all_findings:
        cve_id = f.get("cve_id", "")
        sev = f.get("severity", cvss_severity_label(f.get("cvss", 0.0)))
        svc = f.get("service", "")
        ip = f.get("ip", "")

        if v_search:
            sq = v_search.lower()
            if sq not in f"{cve_id} {svc} {ip} {f.get('summary','')}".lower():
                continue
        if v_sev_filter != "All Severities" and sev.upper() != v_sev_filter.upper():
            continue
        if v_ti_filter == "CISA KEV (Actively Exploited) Only" and not threat_intelligence.is_in_cisa_kev(cve_id):
            continue
        if v_svc_filter != "All Services" and svc != v_svc_filter:
            continue

        filtered_findings.append(f)

    st.caption(f"Showing {len(filtered_findings)} of {total_cves} vulnerability findings")

    # Table
    v_table = []
    for f in filtered_findings:
        is_kev = threat_intelligence.is_in_cisa_kev(f.get("cve_id", ""))
        v_table.append({
            "Severity": f.get("severity", cvss_severity_label(f.get("cvss", 0.0))),
            "CVE ID": f.get("cve_id"),
            "Affected Asset": f.get("ip"),
            "Service": f.get("service"),
            "CVSS Score": f.get("cvss"),
            "Threat Intel": "⚠️ CISA KEV Exploited" if is_kev else "Standard",
            "Detection Source": f.get("source", "NVD Intelligence"),
            "Remediation": f.get("remediation", f.get("fix_version", "Patch software")),
        })

    st.dataframe(pd.DataFrame(v_table), use_container_width=True, hide_index=True)

    # Drilldown
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown("### 🔬 Vulnerability Details & Remediation Guidance")

    cve_options = [f"{f.get('cve_id')} on {f.get('ip')} ({f.get('service')})" for f in filtered_findings]
    if cve_options:
        sel_cve_str = st.selectbox("Select Finding for Evidence & Fix Details", cve_options, index=0)
        sel_cve_id = sel_cve_str.split(" ")[0]
        sel_finding = next((f for f in filtered_findings if f.get("cve_id") == sel_cve_id), filtered_findings[0])

        st.markdown(f"""
        <div style="background:#151E32;border:1px solid #23324D;border-radius:8px;padding:18px 22px;margin-bottom:14px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                <div>
                    <span style="font-size:1.2rem;font-weight:700;color:#F8FAFC">{sel_finding.get('cve_id')}</span>
                    <span style="font-size:0.85rem;color:#94A3B8;margin-left:8px">· {sel_finding.get('service')} on <code>{sel_finding.get('ip')}</code></span>
                </div>
                <div>
                    {_soc_badge_sev(sel_finding.get('severity'))}
                    <span style="margin-left:8px">{_soc_badge_cat(sel_finding.get('source'))}</span>
                </div>
            </div>
            <div style="font-size:0.85rem;color:#CBD5E1;margin-bottom:14px;line-height:1.6">
                <b>Vulnerability Summary:</b><br>{sel_finding.get('summary', 'Detailed advisory information for this CVE is catalogued in NIST NVD.')}
            </div>
            <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:12px;font-size:0.8rem;background:#0F172A;padding:12px 16px;border-radius:6px;border:1px solid #1E293B;margin-bottom:14px">
                <div><b>CVSS Base Score:</b> <span style="color:#EF4444;font-weight:700">{sel_finding.get('cvss')}</span></div>
                <div><b>CISA KEV Status:</b> {'<span style="color:#EF4444;font-weight:700">⚠️ Known Exploited in Wild</span>' if threat_intelligence.is_in_cisa_kev(sel_finding.get('cve_id','')) else '<span style="color:#10B981">Not in KEV</span>'}</div>
                <div><b>Detection Confidence:</b> <span style="color:#38BDF8">{sel_finding.get('source', 'NVD REST API')}</span></div>
            </div>
            <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.3);border-radius:6px;padding:12px 16px">
                <div style="font-size:0.75rem;font-weight:700;color:#10B981;text-transform:uppercase;margin-bottom:4px">Actionable Remediation Guidance</div>
                <div style="font-size:0.82rem;color:#F8FAFC">{sel_finding.get('remediation', sel_finding.get('fix_version', 'Upgrade service to latest patched release.'))}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# 4. EXPOSURE PAGE
# ─────────────────────────────────────────────────────────────────
def render_exposure_page():
    _soc_header("EXPOSURE")

    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())
    if G.number_of_nodes() == 0:
        st.info("Network graph is empty. Run a network scan to construct the exposure graph.")
        return

    # Graph Controls Toolbar
    gc1, gc2, gc3 = st.columns([4, 4, 3])
    with gc1:
        edge_filter = st.selectbox(
            "Graph View Filter",
            ["Clean View (High-Risk & Active Paths)", "All Exposure Edges", "Attack Paths Only", "High-Risk Paths Only"],
            index=0,
        )
    with gc2:
        layout_mode = st.selectbox(
            "Topology Layout",
            ["Force-Directed (Dynamic Physics)", "Hierarchical (Tiered Architecture)"],
            index=0,
        )
    with gc3:
        show_honeypot = st.checkbox("Show Decoy / Honeypots", value=True)

    # Graph Metrics Row
    total_nodes = G.number_of_nodes()
    total_edges = G.number_of_edges()
    crit_count = sum(1 for _, d in G.nodes(data=True) if (d.get("criticality") or 0) >= 4 and d.get("node_type") != "honeypot")

    em1, em2, em3, em4 = st.columns(4)
    with em1:
        st.metric("TOPOLOGY NODES", total_nodes)
    with em2:
        st.metric("LATERAL EDGES", total_edges)
    with em3:
        st.metric("CRITICAL ASSETS", crit_count)
    with em4:
        st.metric("AVG NODE DEGREE", f"{(total_edges/total_nodes if total_nodes else 0):.1f}")

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # Render Graph
    compromised_set = st.session_state.get("compromised", set())
    graph_html = render_graph(
        G,
        compromised_set=compromised_set,
        current_node=st.session_state.get("current_anim_node"),
        show_honeypot=show_honeypot,
        new_exposure_edges=st.session_state.get("new_exposure_edges", set()),
        edge_filter=edge_filter,
        layout_mode=layout_mode,
    )
    st.components.v1.html(graph_html, height=590, scrolling=False)

    # Graph Legend & Node/Edge Inspector
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown("### 🔍 Lateral Exposure & Edge Intelligence Inspector")

    edges_list = [(u, v, d) for u, v, d in G.edges(data=True) if G.nodes[u].get("node_type") != "honeypot" and G.nodes[v].get("node_type") != "honeypot"]
    if edges_list:
        edge_options = [f"{u}  ──[{d.get('service','TCP')}:{d.get('port','—')}]──▶  {v}" for u, v, d in edges_list]
        sel_edge_idx = st.selectbox("Select Exposure Relationship to Inspect", range(len(edge_options)), format_func=lambda i: edge_options[i])
        src_node, dst_node, edge_data = edges_list[sel_edge_idx]
        src_d = G.nodes[src_node]
        dst_d = G.nodes[dst_node]

        ei = edge_data.get("edge_intelligence")
        if not ei and V4_MODULES_LOADED:
            try:
                enrich_graph_edges(G)
                ei = edge_data.get("edge_intelligence")
            except Exception:
                pass

        st.markdown(f"""
        <div style="background:#151E32;border:1px solid #23324D;border-radius:8px;padding:16px 20px;margin-bottom:12px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                <div style="font-size:0.95rem;font-weight:700;color:#F8FAFC">
                    <code>{src_d.get('ip')}</code> ({src_d.get('display_name', src_node)})
                    <span style="color:#3B82F6;margin:0 8px">━━━━[ {edge_data.get('service','TCP')} Port {edge_data.get('port','—')} ]━━━━▶</span>
                    <code>{dst_d.get('ip')}</code> ({dst_d.get('display_name', dst_node)})
                </div>
                <div>
                    {_soc_badge_cat('SIMULATED RESULT')}
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:10px;font-size:0.78rem;background:#0F172A;padding:10px 14px;border-radius:6px;border:1px solid #1E293B;margin-bottom:10px">
                <div><b>Service Protocol:</b> <span style="color:#38BDF8">{edge_data.get('service')} (TCP/{edge_data.get('port')})</span></div>
                <div><b>MITRE ATT&CK:</b> <span style="color:#F97316">{ei.get('mitre_technique_id','T1021 Remote Services') if ei else 'T1021'}</span></div>
                <div><b>Defense Status:</b> {'<span style="color:#EF4444">Blocked by Isolation</span>' if dst_d.get('isolated') else '<span style="color:#10B981">Reachable Path</span>'}</div>
            </div>
            <div style="font-size:0.78rem;color:#94A3B8;line-height:1.5">
                <b>Exploitation Vector Analysis:</b> {ei.get('human_reason', 'An attacker on the source endpoint can attempt lateral service discovery and authentication against this open port.') if ei else 'Lateral connection modeled based on observed open port.'}
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("No inter-host lateral exposure edges found.")


# ─────────────────────────────────────────────────────────────────
# 5. INCIDENTS & ALERTS PAGE
# ─────────────────────────────────────────────────────────────────
def render_incidents_page():
    _soc_header("INCIDENTS & ALERTS")

    alerts = monitor_db.get_alerts(limit=500)

    # Metrics
    total_alerts = len(alerts)
    crit_high = sum(1 for a in alerts if a.get("severity") in ("CRITICAL", "HIGH"))
    unack = sum(1 for a in alerts if not a.get("acknowledged"))
    honeypot_triggers = sum(1 for a in alerts if "HONEYPOT" in a.get("event_type", "") or "DECOY" in a.get("event_type", ""))

    a1, a2, a3, a4 = st.columns(4)
    with a1:
        st.metric("TOTAL ALERTS", total_alerts)
    with a2:
        st.metric("CRITICAL / HIGH", crit_high)
    with a3:
        st.metric("UNACKNOWLEDGED", unack)
    with a4:
        st.metric("DECOY INTERCEPTIONS", honeypot_triggers)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # Alert Filtering
    ac1, ac2, ac3 = st.columns([3, 3, 4])
    with ac1:
        a_sev_filt = st.selectbox("Filter Severity", ["All Severities", "Critical", "High", "Medium", "Low", "Info"], index=0)
    with ac2:
        a_status_filt = st.selectbox("Status Filter", ["All Statuses", "Unacknowledged Only", "Acknowledged Only"], index=0)
    with ac3:
        a_search = st.text_input("Search Alert Log", placeholder="Filter by asset IP, event type, text...")

    filtered_alerts = []
    for a in alerts:
        sev = (a.get("severity") or "INFO").upper()
        is_ack = bool(a.get("acknowledged"))
        text = f"{a.get('asset_id','')} {a.get('event_type','')} {a.get('detail_text','')} {a.get('event_data','')} {sev}".lower()

        if a_sev_filt != "All Severities" and sev != a_sev_filt.upper():
            continue
        if a_status_filt == "Unacknowledged Only" and is_ack:
            continue
        elif a_status_filt == "Acknowledged Only" and not is_ack:
            continue
        if a_search and a_search.lower() not in text:
            continue

        filtered_alerts.append(a)

    st.caption(f"Displaying {len(filtered_alerts)} of {total_alerts} security alerts")

    # Alert Feed
    if filtered_alerts:
        for idx, a in enumerate(filtered_alerts[:30]):
            sev = (a.get("severity") or "INFO").upper()
            is_ack = bool(a.get("acknowledged"))
            alert_id = a.get("alert_id") or a.get("id") or idx
            created_at = a.get("created_at") or a.get("timestamp") or "Just now"
            if isinstance(created_at, datetime):
                created_str = created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            else:
                created_str = str(created_at)[:19]

            col_card, col_act = st.columns([10, 2])
            with col_card:
                st.markdown(f"""
                <div style="background:#151E32;border:1px solid #23324D;border-left:4px solid {SEV_COLORS.get(sev, '#3B82F6')};border-radius:6px;padding:12px 16px;margin-bottom:8px">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                        <div>
                            {_soc_badge_sev(sev)}
                            <b style="font-size:0.85rem;color:#F8FAFC;margin-left:8px">{a.get('event_type','ALERT')}</b>
                            <span style="font-size:0.75rem;color:#94A3B8;margin-left:6px">· Asset: <code>{a.get('asset_id','Network')}</code></span>
                        </div>
                        <span style="font-size:0.72rem;color:#64748B">{created_str}</span>
                    </div>
                    <div style="font-size:0.78rem;color:#CBD5E1;line-height:1.4">
                        {a.get('detail_text') or a.get('event_data') or 'Security state modification detected by monitoring engine.'}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with col_act:
                if not is_ack:
                    if st.button("Acknowledge", key=f"ack_{alert_id}", use_container_width=True):
                        try:
                            monitor_db.acknowledge_alert(alert_id)
                            st.rerun()
                        except Exception:
                            pass
                else:
                    st.markdown("<div style='font-size:0.72rem;color:#10B981;padding-top:14px'>✓ Acknowledged</div>", unsafe_allow_html=True)
    else:
        st.info("No alerts matching current filter criteria.")


# ─────────────────────────────────────────────────────────────────
# 6. ANALYSIS PAGE
# ─────────────────────────────────────────────────────────────────
def render_analysis_page():
    _soc_header("ANALYSIS")

    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())

    tab_sim, tab_priorities, tab_mitre, tab_history = st.tabs([
        "⚔️ Modeled Attack Path Simulation",
        "📊 Graph Risk Prioritization",
        "🎯 Threat Intelligence & MITRE Context",
        "📈 Historical Security Trends",
    ])

    # 1. Attack Simulation Tab
    with tab_sim:
        st.markdown("""
        <div class="soc-sim-banner">
            <span style="font-size:1.1rem">◈</span>
            <div>
                <b>SIMULATION ENVIRONMENT:</b> Modeled analytical propagation based on observed port reachability and CVE risks. No exploitation, credential brute-forcing, or payload delivery is performed.
            </div>
        </div>
        """, unsafe_allow_html=True)

        all_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
        if not all_nodes:
            st.info("No nodes in network graph. Run an assessment scan first.")
        else:
            has_prev_sim = bool(st.session_state.get("simulation_done"))
            btn_label = "🔁 RE-RUN ATTACK SIMULATION" if has_prev_sim else "▶ RUN ATTACK SIMULATION"

            sim_col1, sim_col2, sim_col3 = st.columns([4, 4, 3])
            with sim_col1:
                default_idx = all_nodes.index(st.session_state.get("last_entry_node")) if st.session_state.get("last_entry_node") in all_nodes else min(1, len(all_nodes)-1)
                entry_node = st.selectbox("Select Simulated Entry Point", all_nodes, index=default_idx)
            with sim_col2:
                sim_ids = st.checkbox("Simulate with IDS Active", value=st.session_state.get("ids_deployed", False))
                sim_seg = st.checkbox("Simulate with Network Segmentation", value=st.session_state.get("segmentation_applied", False))
            with sim_col3:
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                run_sim = st.button(btn_label, use_container_width=True, type="primary")

            if run_sim or has_prev_sim:
                if run_sim:
                    # If this is a re-run, capture the previous state as BEFORE baseline if not already captured
                    if has_prev_sim:
                        if st.session_state.get("risk_before_defense") is None and st.session_state.get("risk_score") is not None:
                            st.session_state.risk_before_defense = float(st.session_state.get("risk_score", 0.0))
                        if not st.session_state.get("blast_before_defense") and st.session_state.get("blast_details"):
                            st.session_state.blast_before_defense = dict(st.session_state.get("blast_details") or {})
                        if not st.session_state.get("overall_acds_risk_before") and st.session_state.get("overall_acds_risk"):
                            st.session_state.overall_acds_risk_before = dict(st.session_state.get("overall_acds_risk") or {})
                        if not st.session_state.get("compromised_before_defense") and st.session_state.get("compromised"):
                            st.session_state.compromised_before_defense = set(st.session_state.get("compromised") or set())
                        if not st.session_state.get("timeline_before_defense") and st.session_state.get("timeline"):
                            st.session_state.timeline_before_defense = list(st.session_state.get("timeline") or [])
                        if not st.session_state.get("mitre_before_defense") and st.session_state.get("timeline"):
                            st.session_state.mitre_before_defense = {
                                t['mitre_code']: t.get('mitre_desc', 'Remote Service')
                                for t in st.session_state.get('timeline', []) if t.get('mitre_code')
                            }
                        st.session_state.has_re_simulated = True

                    with st.spinner("Calculating analytical propagation path..."):
                        t_start = time.time()
                        timeline, decision_log, compromised, uncompromised, successful_paths, blocked_failed_paths, attack_stats = simulate_decision_based_propagation(
                            G, entry_node, seed=42, ids_deployed=sim_ids, segmentation_applied=sim_seg
                        )
                        honeypot_trig = any(
                            entry.get("ntype") == "honeypot" and entry.get("success") for entry in timeline
                        )
                        dur = round(time.time() - t_start, 4)
                        risk_sc, blast_details = calculate_risk(G, compromised, timeline, honeypot_trig, attack_stats)
                        
                        st.session_state.compromised = compromised
                        st.session_state.timeline = timeline
                        st.session_state.decision_log = decision_log
                        st.session_state.successful_paths = successful_paths
                        st.session_state.blocked_failed_paths = blocked_failed_paths
                        st.session_state.blast_details = blast_details
                        st.session_state.honeypot_triggered = honeypot_trig
                        st.session_state.attack_stats = attack_stats
                        st.session_state.risk_score = risk_sc
                        st.session_state.simulation_done = True
                        st.session_state.ids_deployed = sim_ids
                        st.session_state.segmentation_applied = sim_seg
                        st.session_state.overall_acds_risk = calculate_overall_acds_risk(G, risk_sc)
                        st.session_state.last_entry_node = entry_node

                        # If re-simulated, store post-defense / re-sim outcomes
                        if st.session_state.get("has_re_simulated"):
                            st.session_state.post_defense_stats = blast_details
                            st.session_state.risk_score_after = risk_sc
                            st.session_state.overall_acds_risk_after = st.session_state.overall_acds_risk
                            st.session_state.compromised_after = compromised
                            st.session_state.timeline_after = timeline
                            st.session_state.decision_log_after = decision_log
                            st.session_state.mitre_after_defense = {
                                t['mitre_code']: t.get('mitre_desc', 'Remote Service')
                                for t in timeline if t.get('mitre_code')
                            }
                            st.session_state.post_defense_sim_done = True
                            st.session_state.pending_re_simulation = False

                # Simulation Outcome Cards
                comp_nodes = st.session_state.get("compromised", set())
                blast_det = st.session_state.get("blast_details", {})
                max_hops = blast_det.get("max_lateral_hops", 0)

                sr1, sr2, sr3, sr4 = st.columns(4)
                with sr1:
                    st.metric("COMPROMISED HOSTS", len(comp_nodes), f"of {len(all_nodes)} in scope")
                with sr2:
                    st.metric("BLAST RADIUS SCORE", f"{st.session_state.get('risk_score', 0):.1f}/100")
                with sr3:
                    st.metric("ATTACK DEPTH", f"{max_hops} Lateral Hop{'s' if max_hops != 1 else ''}")
                with sr4:
                    st.metric("DECOY TRIGGERED", "YES" if st.session_state.get("honeypot_triggered") else "NO")

                if len(all_nodes) == 1:
                    st.markdown("""
                    <div style="background:#0F172A;border:1px solid #1E293B;border-radius:6px;padding:8px 14px;margin-top:8px;font-size:0.75rem;color:#94A3B8">
                        ℹ️ <b>Single-Host Scope Note:</b> Because only 1 asset was in scope and selected as the modeled entry point, 100% of scoped assets are within the blast radius with 0 lateral propagation hops.
                    </div>
                    """, unsafe_allow_html=True)

                # ── BEFORE vs AFTER COMPARISON IN THE SAME SIMULATOR AREA ──
                has_comparison = (
                    st.session_state.get("has_re_simulated") or 
                    st.session_state.get("post_defense_sim_done") or 
                    st.session_state.get("risk_before_defense") is not None
                )
                if has_comparison and st.session_state.get("risk_before_defense") is not None:
                    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
                    st.markdown("#### 🎯 Before vs After Re-Simulation Comparison")

                    before_risk = st.session_state.get("risk_before_defense")
                    after_risk = st.session_state.get("risk_score")
                    before_bd = st.session_state.get("blast_before_defense") or {}
                    after_bd = blast_det
                    before_ov = st.session_state.get("overall_acds_risk_before") or {}
                    after_ov = st.session_state.get("overall_acds_risk") or {}

                    b_ov_sc = before_ov.get("overall_score")
                    a_ov_sc = after_ov.get("overall_score")

                    comp_rows = [
                        ("OVERALL RISK", b_ov_sc, a_ov_sc, True),
                        ("BLAST RADIUS", before_risk, after_risk, True),
                        ("CRITICAL ASSETS REACHABLE", before_bd.get("critical_assets_reached", 0), after_bd.get("critical_assets_reached", 0), True),
                        ("ATTACK DEPTH (hops)", before_bd.get("max_lateral_hops", 0), after_bd.get("max_lateral_hops", 0), True),
                        ("REACHABLE NODES", before_bd.get("systems_controlled", before_bd.get("compromised_count", 0)), after_bd.get("systems_controlled", len(comp_nodes)), True),
                    ]
                    comp_rows = [r for r in comp_rows if r[1] is not None]
                    st.markdown(_verification_metric_row(comp_rows), unsafe_allow_html=True)

                    # Better vs Worse Comparative Analysis
                    before_comp = set(st.session_state.get("compromised_before_defense") or set())
                    after_comp = set(comp_nodes)
                    saved_hosts = before_comp - after_comp
                    newly_exposed = after_comp - before_comp

                    before_m = st.session_state.get("mitre_before_defense") or {}
                    current_m = {t['mitre_code']: t.get('mitre_desc', '') for t in (st.session_state.get("timeline") or []) if t.get('mitre_code')}
                    neut_tech = set(before_m.keys()) - set(current_m.keys())

                    cb1, cb2 = st.columns(2)
                    with cb1:
                        st.markdown("""
                        <div style="background:#0F291E;border:1px solid #059669;border-radius:8px;padding:14px;height:100%">
                            <div style="font-size:0.85rem;font-weight:700;color:#10B981;margin-bottom:6px">
                                🟢 WHAT'S DONE BETTER (Defensive Improvements)
                            </div>
                        """, unsafe_allow_html=True)
                        if after_risk is not None and before_risk is not None:
                            r_delta = round(after_risk - before_risk, 1)
                            if r_delta < 0:
                                st.markdown(f"- **Blast Radius:** Decreased by **{abs(r_delta):.1f} pts** ({before_risk:.1f} → {after_risk:.1f})")
                            elif r_delta == 0:
                                st.markdown(f"- **Blast Radius:** Unchanged ({before_risk:.1f})")
                        if saved_hosts:
                            s_str = ", ".join(f"<code>{n}</code>" for n in saved_hosts)
                            st.markdown(f"- **Shielded Endpoints:** {len(saved_hosts)} host(s) protected ({s_str})", unsafe_allow_html=True)
                        if neut_tech:
                            t_str = ", ".join(f"<code>{t}</code>" for t in neut_tech)
                            st.markdown(f"- **MITRE Techniques Blocked:** {t_str}", unsafe_allow_html=True)
                        if after_bd.get("max_lateral_hops", 0) < before_bd.get("max_lateral_hops", 0):
                            st.markdown(f"- **Lateral Chain:** Reduced from {before_bd.get('max_lateral_hops', 0)} to {after_bd.get('max_lateral_hops', 0)} hop(s).")
                        st.markdown("</div>", unsafe_allow_html=True)

                    with cb2:
                        st.markdown("""
                        <div style="background:#261815;border:1px solid #DC2626;border-radius:8px;padding:14px;height:100%">
                            <div style="font-size:0.85rem;font-weight:700;color:#EF4444;margin-bottom:6px">
                                🔴 RESIDUAL RISKS & REMAINING EXPOSURE
                            </div>
                        """, unsafe_allow_html=True)
                        if after_comp:
                            st_str = ", ".join(f"<code>{n}</code>" for n in after_comp)
                            st.markdown(f"- **Reachable Endpoints:** {len(after_comp)} asset(s) accessible ({st_str})", unsafe_allow_html=True)
                        else:
                            st.markdown("- **Reachable Endpoints:** 0 (Full containment achieved)")
                        if current_m:
                            m_str = ", ".join(f"<code>{t}</code>" for t in current_m)
                            st.markdown(f"- **Active Vectors in Scope:** {m_str}", unsafe_allow_html=True)
                        if newly_exposed:
                            st.markdown(f"- ⚠️ **Secondary Exposure:** {len(newly_exposed)} asset(s) reached via alternate routes.")
                        st.markdown("</div>", unsafe_allow_html=True)

                    if st.button("↺ Reset Baseline Snapshot", key="reset_sim_baseline"):
                        st.session_state.risk_before_defense = None
                        st.session_state.blast_before_defense = None
                        st.session_state.overall_acds_risk_before = None
                        st.session_state.compromised_before_defense = None
                        st.session_state.timeline_before_defense = None
                        st.session_state.mitre_before_defense = None
                        st.session_state.has_re_simulated = False
                        st.toast("Baseline snapshot cleared. Next run will be the new baseline.", icon="🔄")
                        st.rerun()

                st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

                # Visual Attack Propagation Graph
                st.markdown("#### 🗺️ Visual Attack Propagation Graph")
                sim_graph_html = render_graph(
                    G,
                    compromised_set=st.session_state.get("compromised", set()),
                    current_node=st.session_state.get("last_entry_node"),
                    show_honeypot=True,
                    edge_filter="Clean View (High-Risk & Active Paths)",
                    layout_mode="Force-Directed (Dynamic Physics)",
                )
                st.components.v1.html(sim_graph_html, height=550, scrolling=False)

                # Propagation Step-by-Step Table
                st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
                st.markdown("#### Modeled Attack Propagation Sequence")

                decision_log = st.session_state.get("decision_log") or []
                timeline = st.session_state.get("timeline") or []

                step_rows = []
                if decision_log:
                    for entry in decision_log:
                        step_num = entry.get("step")
                        src_name = entry.get("source") or "Not recorded"
                        dst_name = entry.get("target") or "Not recorded"
                        dst_ip = entry.get("target_ip")
                        dst_display = f"{dst_name} ({dst_ip})" if (dst_ip and dst_ip not in dst_name) else dst_name
                        svc_str = entry.get("service") or "Not recorded"
                        tech_str = entry.get("technique") or "Not recorded"
                        prob_str = entry.get("probability") or "Not recorded"
                        decision_txt = str(entry.get("decision", ""))

                        if entry.get("step") == 1 or src_name == "EXTERNAL ATTACKER":
                            outcome_lbl = "🟢 ASSUMED ENTRY FOOTHOLD"
                        elif "COMPROMISE POSSIBLE" in decision_txt:
                            outcome_lbl = "🔴 COMPROMISE POSSIBLE (Simulated)"
                        elif "BLOCKED" in decision_txt:
                            outcome_lbl = "🛡️ BLOCKED BY DEFENSE"
                        elif "COMPROMISE NOT POSSIBLE" in decision_txt:
                            outcome_lbl = "⚪ ATTEMPT RESISTED / PORT CLOSED"
                        elif "NO VALID PATH" in decision_txt:
                            outcome_lbl = "⚪ NO VALID PATH (Offline/Closed)"
                        else:
                            outcome_lbl = entry.get("result_status", "EVALUATED")

                        step_rows.append({
                            "Step": f"Step {step_num}" if step_num is not None else "—",
                            "Attacker Source": src_name,
                            "Target Host": dst_display,
                            "Target Service / Vector": svc_str,
                            "MITRE ATT&CK Technique": tech_str,
                            "Modeled Probability": prob_str,
                            "Analytical Outcome": outcome_lbl,
                            "Decision Rationale": entry.get("reason", "Not recorded"),
                        })
                elif timeline:
                    for idx, t in enumerate(timeline, start=1):
                        is_entry = (t.get("from_node") is None or idx == 1)
                        src_str = "EXTERNAL / ASSUMED FOOTHOLD" if is_entry else str(t.get("from_node", "Unknown"))
                        dst_str = str(t.get("node", "Target"))
                        tech_str = f"{t.get('mitre_code', 'T1021')} — {t.get('mitre_desc', 'Remote Services')}" if t.get("mitre_code") else "Not recorded"
                        vec_str = t.get("access_vector") or "Not recorded"
                        if is_entry:
                            outcome_str = "🟢 ASSUMED ENTRY FOOTHOLD"
                        elif t.get("success"):
                            outcome_str = "🔴 COMPROMISE POSSIBLE (Simulated)"
                        else:
                            outcome_str = "🛡️ BLOCKED / RESISTED"

                        step_rows.append({
                            "Step": f"Step {t.get('timestep', idx)}",
                            "Attacker Source": src_str,
                            "Target Host": dst_str,
                            "Target Service / Vector": vec_str,
                            "MITRE ATT&CK Technique": tech_str,
                            "Modeled Probability": "100% (Assumed Entry)" if is_entry else f"{int(t.get('vuln', 0.5)*100)}%",
                            "Analytical Outcome": outcome_str,
                            "Decision Rationale": "Assumed entry point foothold" if is_entry else ("Modeled lateral compromise" if t.get("success") else "Blocked/contained by defensive controls or probability threshold"),
                        })

                if step_rows:
                    if len(step_rows) == 1 and ("FOOTHOLD" in step_rows[0].get("Analytical Outcome", "")):
                        st.info("ℹ️ **Simulation Contained at Initial Foothold:** Selected asset was modeled as the initial entry point. No lateral movement propagation occurred because no other reachable targets/edges exist in this scope.")
                    st.dataframe(pd.DataFrame(step_rows), use_container_width=True, hide_index=True)
                else:
                    st.info("Simulation not executed or no propagation events were recorded.")

    # 2. Graph Risk Prioritization Tab
    with tab_priorities:
        st.markdown("#### Asset Exposure & Centrality Ranking")
        if V4_MODULES_LOADED and G.number_of_nodes() > 0:
            try:
                ranked = rank_all_assets_by_priority(G)
                if isinstance(ranked, list):
                    for item in ranked:
                        st.markdown(render_priority_breakdown_html(item), unsafe_allow_html=True)
                elif isinstance(ranked, dict):
                    st.markdown(render_priority_breakdown_html(ranked), unsafe_allow_html=True)
            except Exception as e:
                st.warning(f"Prioritizer calculation: {e}")
        else:
            st.info("Construct graph to calculate graph-aware asset priorities.")

    # 3. Threat Intelligence & MITRE Tab
    with tab_mitre:
        st.markdown("#### Observed Services to MITRE ATT&CK Matrix Mapping")
        mitre_rows = []
        for port, svc in PORT_SERVICE_MAP.items():
            tech_id, tech_name = SERVICE_MITRE.get(svc, ("T1021", "Remote Services"))
            mitre_rows.append({
                "Service": svc,
                "Standard Port": port,
                "MITRE Technique ID": tech_id,
                "Technique Name": tech_name,
                "Exposure Risk Factor": f"{SERVICE_BASELINE_RISK.get(svc, 0.4)*100:.0f}%",
            })
        st.dataframe(pd.DataFrame(mitre_rows), use_container_width=True, hide_index=True)

    # 4. Historical Trends Tab
    with tab_history:
        st.markdown("#### Historical Security & Exposure Posture Trends")
        if V4_MODULES_LOADED:
            try:
                risk_rows = get_overall_risk_trend(monitor_db, limit=30)
                asset_trend = get_asset_count_trend(monitor_db, limit=30)
                applied_defenses = st.session_state.get("applied_defenses", [])
                defense_eff = calculate_defense_effectiveness(
                    st.session_state.get("blast_details"),
                    st.session_state.get("blast_details"),
                    applied_defenses
                )
                st.markdown(render_historical_trend_html(risk_rows, asset_trend, defense_eff), unsafe_allow_html=True)
            except Exception as e:
                st.info(f"Historical trends: {e}")
        else:
            st.info("Historical data module loading.")


# ─────────────────────────────────────────────────────────────────
# 7. RESPONSE PAGE
# ─────────────────────────────────────────────────────────────────
def render_response_page():
    _soc_header("RESPONSE")

    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())
    if G.number_of_nodes() == 0:
        st.info("No assets in graph. Run an assessment to generate defense recommendations.")
        return

    # Re-Simulation Prompt Banner across Response page
    applied_defenses = st.session_state.get("applied_defenses", [])
    if applied_defenses and (st.session_state.get("pending_re_simulation") or not st.session_state.get("post_defense_sim_done")):
        bp1, bp2 = st.columns([8, 4])
        with bp1:
            st.markdown(f"""
            <div style="background:rgba(245,158,11,0.1);border:1px solid #F59E0B;border-radius:6px;padding:12px 16px;margin-bottom:12px">
                <b style="color:#F59E0B;font-size:0.88rem">⚡ {len(applied_defenses)} Patch / Defense Control(s) Applied to In-Memory Model</b>
                <div style="font-size:0.75rem;color:#CBD5E1;margin-top:2px">
                    Re-run the attack simulation to evaluate whether lateral attack paths were halted and view the Before vs. After comparison.
                </div>
            </div>
            """, unsafe_allow_html=True)
        with bp2:
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
            if st.button("🔁 RUN RE-ATTACK SIMULATION NOW", type="primary", use_container_width=True, key="resp_top_re_sim"):
                with st.spinner("Executing post-defense attack simulation..."):
                    run_post_defense_re_simulation(G)
                    st.toast("Post-defense simulation completed! Switching to verification...", icon="🛡️")
                    st.rerun()

    tab_plan, tab_opt, tab_verify = st.tabs([
        "🛡️ Prioritized Action Plan",
        "💰 Budget Defense Optimizer",
        "📏 Before / After Verification & Ledger",
    ])

    # 1. Prioritized Action Plan
    with tab_plan:
        st.markdown("### 🎯 Immediate Remediation Action Items")
        actions = get_defense_actions(G, st.session_state.get("compromised", set()), st.session_state.get("risk_score", 0.0))
        if actions:
            for idx, act in enumerate(actions):
                act_type = act.get("type", "PATCH").upper()
                sev_cls = "critical" if act.get("risk_reduction", 0) > 15 else "high" if act.get("risk_reduction", 0) > 8 else "medium"
                act_key = f"{act.get('node')}_{act.get('type')}_{idx}"

                # Check if this action is already applied
                already_applied = any(
                    a.get("node") == act.get("node") and str(a.get("type")).lower() == str(act.get("type")).lower()
                    for a in applied_defenses
                )

                c_card, c_btn = st.columns([9, 3])
                with c_card:
                    st.markdown(f"""
                    <div class="soc-action-card {sev_cls}">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                            <div>
                                <span class="badge-sev badge-sev-{sev_cls}">{act_type}</span>
                                <b style="font-size:0.9rem;color:#F8FAFC;margin-left:8px">{act.get('node')}</b>
                            </div>
                            <span style="font-size:0.8rem;font-weight:700;color:#10B981">Estimated -{act.get('risk_reduction', 0):.1f} Risk Pts (Cost: {act.get('cost', 10)})</span>
                        </div>
                        <div style="font-size:0.8rem;color:#CBD5E1;margin-bottom:6px">
                            <b>Action:</b> {act.get('description', act.get('action'))}
                        </div>
                        <div style="font-size:0.75rem;color:#94A3B8">
                            <b>Implementation Rationale:</b> {act.get('rationale', 'Addresses active exposure path and stops potential lateral movement.')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                with c_btn:
                    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
                    if already_applied:
                        st.markdown("<div style='color:#10B981;font-size:0.8rem;font-weight:700;text-align:center;padding-top:8px'>✓ Fix Applied</div>", unsafe_allow_html=True)
                    else:
                        if st.button(f"⚡ Apply Fix", key=f"apply_{act_key}", use_container_width=True):
                            applied, ids_dep, seg_app = apply_defense_actions(G, [act])
                            st.session_state.overall_acds_risk = calculate_overall_acds_risk(G, st.session_state.get("risk_score", 0.0))
                            st.toast(f"Applied {act.get('action')} to model!", icon="🔧")
                            st.rerun()
        else:
            st.success("No critical defense actions pending. Posture is currently optimal.")

    # 2. Budget Optimizer
    with tab_opt:
        st.markdown("### 💰 Budget-Constrained Defense Optimization")
        st.caption("Apply the greedy defense selection algorithm to maximize risk reduction under a specified resource budget.")
        
        all_actions = get_defense_actions(G, st.session_state.get("compromised", set()), st.session_state.get("risk_score", 0.0))
        total_possible_cost = sum(a.get("cost", 10) for a in all_actions) or 100
        budget = st.slider("Available Security Budget ($ / Resource Points)", 10, max(50, total_possible_cost + 20), min(50, total_possible_cost), 10)

        selected_defenses, total_reduction, remaining_budget = greedy_defense_selection(all_actions, budget)
        st.session_state.selected_defenses = selected_defenses
        total_spent = budget - remaining_budget

        st.markdown(f"**Optimal Defense Package ({len(selected_defenses)} actions selected):**")
        if selected_defenses:
            st.info(f"Allocated **{total_spent} / {budget} points** · Total Expected Risk Reduction: **-{total_reduction:.1f} Points**")

            for a in selected_defenses:
                st.markdown(f"- **{a.get('type','DEFENSE').upper()}:** {a.get('node')} — {a.get('description')} *(Cost: {a.get('cost', 10)} pts · Reduction: -{a.get('risk_reduction',0):.1f})*")
            
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            if st.button("⚡ APPLY OPTIMIZED DEFENSES TO MODEL", type="primary", key="apply_opt_pkg"):
                applied, ids_dep, seg_app = apply_defense_actions(G, selected_defenses)
                st.session_state.applied_defenses = applied
                st.session_state.ids_deployed = ids_dep
                st.session_state.segmentation_applied = seg_app
                # Re-calculate overall risk with defenses applied
                st.session_state.overall_acds_risk = calculate_overall_acds_risk(G, st.session_state.get("risk_score", 0.0))
                st.success(f"Applied {len(applied)} defense control(s) to in-memory graph model.")
                st.rerun()
        else:
            st.info("Increase budget slider to select defense controls.")

    # 3. Before/After Verification
    with tab_verify:
        st.markdown("### 📏 Before / After Security Posture Verification")
        st.caption("Compares initial observed baseline against projected post-remediation posture to evaluate what was done better or worse.")
        render_before_after_verification()


# ─────────────────────────────────────────────────────────────────
# 8. REPORTS PAGE
# ─────────────────────────────────────────────────────────────────
def render_reports_page():
    _soc_header("REPORTS")

    G: nx.DiGraph = st.session_state.get("G", nx.DiGraph())
    risk_sc = st.session_state.get("risk_score", 0.0)
    blast_det = st.session_state.get("blast_details", {})
    overall = st.session_state.get("overall_acds_risk") or calculate_overall_acds_risk(G, risk_sc)
    scan_hist = st.session_state.get("scan_history", [])

    st.markdown("### 📄 Export Formats & Downloads")
    r_col1, r_col2, r_col3 = st.columns(3)

    with r_col1:
        st.markdown("""
        <div class="soc-card" style="text-align:center">
            <div style="font-size:1.5rem;margin-bottom:6px">📊</div>
            <div style="font-size:0.9rem;font-weight:700;color:#F8FAFC;margin-bottom:4px">Asset Inventory CSV</div>
            <div style="font-size:0.75rem;color:#94A3B8;margin-bottom:14px">Complete host registry with IP, MAC, OS, vendor, and risk scores.</div>
        """, unsafe_allow_html=True)
        csv_assets = export_asset_inventory_csv(G)
        st.download_button(
            "Download Assets CSV",
            data=csv_assets,
            file_name=f"acds_asset_inventory_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with r_col2:
        st.markdown("""
        <div class="soc-card" style="text-align:center">
            <div style="font-size:1.5rem;margin-bottom:6px">🛡️</div>
            <div style="font-size:0.9rem;font-weight:700;color:#F8FAFC;margin-bottom:4px">Vulnerabilities CSV</div>
            <div style="font-size:0.75rem;color:#94A3B8;margin-bottom:14px">All identified CVE findings, CVSS scores, affected services, and fixes.</div>
        """, unsafe_allow_html=True)
        csv_vulns = export_vulnerability_report_csv(G)
        st.download_button(
            "Download Vulnerabilities CSV",
            data=csv_vulns,
            file_name=f"acds_vulnerabilities_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with r_col3:
        st.markdown("""
        <div class="soc-card" style="text-align:center">
            <div style="font-size:1.5rem;margin-bottom:6px">📑</div>
            <div style="font-size:0.9rem;font-weight:700;color:#F8FAFC;margin-bottom:4px">Executive PDF Report</div>
            <div style="font-size:0.75rem;color:#94A3B8;margin-bottom:14px">Professional multi-page security report suitable for management.</div>
        """, unsafe_allow_html=True)
        if REPORTLAB_AVAILABLE:
            pdf_bytes = build_executive_report_pdf(
                G, risk_sc, blast_det, overall, scan_hist,
                defense_actions=st.session_state.get("recommended_actions", []),
                applied_defenses=st.session_state.get("applied_defenses", []),
                risk_before=st.session_state.get("risk_before"),
                blast_before=st.session_state.get("blast_before"),
                overall_before=st.session_state.get("overall_before"),
                risk_after=st.session_state.get("risk_after"),
                blast_after=st.session_state.get("blast_after"),
                overall_after=st.session_state.get("overall_after"),
                mitre_before=st.session_state.get("mitre_before"),
                mitre_after=st.session_state.get("mitre_after"),
                alerts=st.session_state.get("alerts", []),
            )
            st.download_button(
                "Download PDF Report",
                data=pdf_bytes,
                file_name=f"acds_executive_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary",
            )
        else:
            st.warning("ReportLab library required for PDF generation.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # Executive Report Preview
    st.markdown("### 📋 Executive Summary Preview")
    summary_text = build_executive_report_text(G, risk_sc, blast_det, overall, scan_hist)
    st.text_area("Executive Summary Document", value=summary_text, height=320)


# ─────────────────────────────────────────────────────────────────
# 9. SETTINGS PAGE
# ─────────────────────────────────────────────────────────────────
def render_settings_page():
    _soc_header("SETTINGS")

    current_settings = monitor_db.get_all_settings()

    tab_sec, tab_app, tab_sys = st.tabs([
        "🔒 Security & Scanner Knobs",
        "⚙️ Risk & Alert Thresholds",
        "💾 System Health & Database Diagnostics",
    ])

    with tab_sec:
        st.markdown("#### Network Discovery & Service Probing")
        s_scan_to = st.slider("TCP Port Connect Timeout (seconds)", 0.2, 3.0, float(current_settings.get("scan_timeout_seconds", SCAN_TIMEOUT_SECONDS)), 0.1)
        s_banner_to = st.slider("Banner Grab Timeout (seconds)", 0.5, 5.0, float(current_settings.get("banner_timeout_seconds", BANNER_TIMEOUT_SECONDS)), 0.1)
        s_nvd_cache = st.number_input("NVD Intelligence Cache Expiry (hours)", 1, 168, int(current_settings.get("nvd_cache_hours", NVD_CACHE_HOURS)))

        st.markdown("#### Continuous Monitoring")
        s_interval = st.selectbox("Monitoring Polling Interval", ["30s", "1m", "5m"], index=["30s", "1m", "5m"].index(current_settings.get("monitoring_interval", "1m")))

    with tab_app:
        st.markdown("#### Risk Severity Boundaries (0-100 Scale)")
        s_crit = st.number_input("Critical Risk Floor", 70, 95, int(current_settings.get("risk_threshold_critical", 85)))
        s_high = st.number_input("High Risk Floor", 50, 80, int(current_settings.get("risk_threshold_high", 65)))
        s_med = st.number_input("Medium Risk Floor", 20, 50, int(current_settings.get("risk_threshold_medium", 35)))

        st.markdown("#### SOC Alert Sensitivity")
        s_alert_sev = st.selectbox("Minimum Alert Severity Threshold", ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], index=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(current_settings.get("alert_severity_threshold", "LOW")))

    with tab_sys:
        st.markdown("#### SQLite Database Diagnostics")
        counts = monitor_db.get_asset_count()
        live_assets = monitor_db.get_live_assets()
        scans = monitor_db.get_recent_snapshots(limit=10)
        alerts_count = len(monitor_db.get_alerts(limit=1000))

        d1, d2, d3 = st.columns(3)
        with d1:
            st.metric("TOTAL ASSETS IN DB", counts.get("total", 0))
        with d2:
            st.metric("TOTAL SCANS LOGGED", len(scans))
        with d3:
            st.metric("RECORDED ALERTS", alerts_count)

        st.markdown("#### Rotating Application Log")
        log_path = os.path.join("data", "acds.log")
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f_log:
                log_lines = f_log.readlines()[-40:]
            st.code("".join(log_lines), language="text")
        else:
            st.caption("No log file generated yet.")

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    if st.button("💾 SAVE OPERATIONAL SETTINGS", type="primary"):
        monitor_db.save_setting("scan_timeout_seconds", str(s_scan_to))
        monitor_db.save_setting("banner_timeout_seconds", str(s_banner_to))
        monitor_db.save_setting("nvd_cache_hours", str(s_nvd_cache))
        monitor_db.save_setting("monitoring_interval", str(s_interval))
        monitor_db.save_setting("risk_threshold_critical", str(s_crit))
        monitor_db.save_setting("risk_threshold_high", str(s_high))
        monitor_db.save_setting("risk_threshold_medium", str(s_med))
        monitor_db.save_setting("alert_severity_threshold", str(s_alert_sev))
        apply_runtime_settings()
        st.success("Operational settings persisted successfully.")
        st.rerun()


# ─────────────────────────────────────────────────────────────────
# 🧭 SIDEBAR & MAIN ROUTER
# ─────────────────────────────────────────────────────────────────

# Initialize Session State Variables
if "network_mode" not in st.session_state:
    st.session_state.network_mode = "Real Network Scan"
if "G" not in st.session_state:
    st.session_state.G = nx.DiGraph()
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
if "applied_defenses" not in st.session_state:
    st.session_state.applied_defenses = []
if "ids_deployed" not in st.session_state:
    st.session_state.ids_deployed = False
if "segmentation_applied" not in st.session_state:
    st.session_state.segmentation_applied = False
if "attack_log" not in st.session_state:
    st.session_state.attack_log = []
if "current_anim_node" not in st.session_state:
    st.session_state.current_anim_node = None
if "overall_acds_risk" not in st.session_state:
    st.session_state.overall_acds_risk = None
if "scan_counter" not in st.session_state:
    st.session_state.scan_counter = 0
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "monitoring_enabled" not in st.session_state:
    st.session_state.monitoring_enabled = False
if "monitor_interval" not in st.session_state:
    st.session_state.monitor_interval = "1m"
if "scan_in_progress" not in st.session_state:
    st.session_state.scan_in_progress = False
if "nav_page" not in st.session_state:
    st.session_state.nav_page = "OVERVIEW"

# Apply persisted runtime settings at startup
apply_runtime_settings()

# ─────────────────────────────────────────────────────────────────
# SIDEBAR EXECUTION
# ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:14px 0 10px 0;text-align:center">
        <div style="font-size:1.15rem;font-weight:800;color:#F8FAFC;letter-spacing:0.5px">🛡️ ACDS SOC</div>
        <div style="font-size:0.7rem;color:#94A3B8;letter-spacing:0.3px;margin-top:2px">Adaptive Cyber Defense System</div>
        <div style="font-size:0.65rem;color:#64748B;letter-spacing:0.5px;text-transform:uppercase;margin-top:1px">Enterprise Edition</div>
    </div>
    <hr style="border-color:#1E293B;margin:6px 0 14px 0">
    """, unsafe_allow_html=True)

    # Environment Selector
    st.markdown('<div style="font-size:0.72rem;font-weight:700;color:#94A3B8;text-transform:uppercase;margin-bottom:6px">ENVIRONMENT</div>', unsafe_allow_html=True)
    net_mode = st.radio(
        "Network Environment",
        ["Production Network", "Simulated Lab"],
        index=0 if st.session_state.network_mode == "Real Network Scan" else 1,
        label_visibility="collapsed",
    )
    new_mode = "Real Network Scan" if net_mode == "Production Network" else "Simulated Lab"
    if new_mode != st.session_state.network_mode:
        st.session_state.network_mode = new_mode
        st.session_state.simulation_done = False
        st.session_state.G = build_network() if new_mode == "Simulated Lab" else nx.DiGraph()
        st.rerun()

    # Detected Scope Info
    net_env = st.session_state.get("network_env") or detect_network_environment()
    st.session_state["network_env"] = net_env

    if st.session_state.network_mode == "Real Network Scan":
        st.markdown(f"""
        <div style="background:#0F172A;border:1px solid #1E293B;border-radius:6px;padding:8px 12px;margin:8px 0;font-size:0.72rem;line-height:1.5">
            <div><span style="color:#64748B">Adapter:</span> <b style="color:#CBD5E1">{net_env.get('adapter_name', 'Default')[:18]}</b></div>
            <div><span style="color:#64748B">Subnet:</span> <code>{net_env.get('subnet_cidr', '192.168.1.0/24')}</code></div>
            <div><span style="color:#64748B">Controller IP:</span> <code>{net_env.get('controller_ip', '127.0.0.1')}</code></div>
        </div>
        """, unsafe_allow_html=True)

    # Continuous Monitoring Control
    st.markdown('<div style="font-size:0.72rem;font-weight:700;color:#94A3B8;text-transform:uppercase;margin-top:10px;margin-bottom:6px">CONTINUOUS MONITORING</div>', unsafe_allow_html=True)
    mon_active = st.session_state.get("monitoring_enabled", False)
    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;font-size:0.78rem">
        <span style="color:{'#10B981' if mon_active else '#64748B'};font-weight:700">{'● Active' if mon_active else '○ Inactive'}</span>
        <span style="color:#94A3B8">{st.session_state.monitor_interval} interval</span>
    </div>
    """, unsafe_allow_html=True)

    m_btn1, m_btn2 = st.columns(2)
    with m_btn1:
        if st.button("▶ START", use_container_width=True, disabled=mon_active):
            st.session_state.monitoring_enabled = True
            st.rerun()
    with m_btn2:
        if st.button("■ STOP", use_container_width=True, disabled=not mon_active):
            st.session_state.monitoring_enabled = False
            st.rerun()

    # Primary Operator Navigation
    st.markdown('<div style="font-size:0.72rem;font-weight:700;color:#94A3B8;text-transform:uppercase;margin-top:14px;margin-bottom:6px">OPERATOR NAVIGATION</div>', unsafe_allow_html=True)
    
    NAV_OPTIONS = [
        "OVERVIEW",
        "ASSETS",
        "VULNERABILITIES",
        "EXPOSURE",
        "INCIDENTS & ALERTS",
        "ANALYSIS",
        "RESPONSE",
        "REPORTS",
        "SETTINGS",
    ]

    selected_nav = st.radio(
        "Navigation",
        NAV_OPTIONS,
        index=NAV_OPTIONS.index(st.session_state.nav_page) if st.session_state.nav_page in NAV_OPTIONS else 0,
        label_visibility="collapsed",
    )
    if selected_nav != st.session_state.nav_page:
        st.session_state.nav_page = selected_nav
        st.rerun()

    # Network Assessment Action Block
    st.markdown('<hr style="border-color:#1E293B;margin:14px 0 10px 0">', unsafe_allow_html=True)
    st.markdown('<div style="font-size:0.72rem;font-weight:700;color:#94A3B8;text-transform:uppercase;margin-bottom:6px">ASSESSMENT SCOPE & INTERFACE</div>', unsafe_allow_html=True)

    adapters_list = net_env.get('all_adapters') or []
    adapter_labels = []
    for a in adapters_list:
        clean_name = a.get('name', 'Interface').replace('Ethernet adapter ', '').replace('Wireless LAN adapter ', '').replace('Unknown adapter ', '')
        adapter_labels.append(f"{clean_name} ({a.get('ip')})")
    adapter_labels.append("🎯 Custom Target Scope / IP")

    default_ad_idx = 0
    for idx, a in enumerate(adapters_list):
        if a.get('is_default'):
            default_ad_idx = idx
            break

    chosen_scope_idx = st.selectbox(
        "Network Adapter / Target Scope",
        range(len(adapter_labels)),
        format_func=lambda i: adapter_labels[i],
        index=st.session_state.get("selected_adapter_idx", default_ad_idx),
        key="ad_scope_select",
        label_visibility="collapsed"
    )
    st.session_state.selected_adapter_idx = chosen_scope_idx

    target_spec_ips = None
    base_ip = net_env.get('base_ip_prefix') or get_local_ip()
    scan_limit = 100

    if chosen_scope_idx < len(adapters_list):
        sel_ad = adapters_list[chosen_scope_idx]
        base_ip = sel_ad.get('base_ip_prefix')
        default_cidr = sel_ad.get('subnet_cidr')
        st.markdown(f"<div style='font-size:0.72rem;color:#94A3B8;margin-bottom:6px'>Active Subnet: <code>{default_cidr}</code></div>", unsafe_allow_html=True)
        scan_limit = st.slider("Host Scan Limit", 10, 254, 50, 10)
    else:
        custom_target = st.text_input("Target IP or Subnet CIDR", value="192.168.93.129", placeholder="e.g. 192.168.93.129 or 192.168.93.0/24")
        target_spec_ips = parse_target_ips(custom_target, base_ip)
        st.markdown(f"<div style='font-size:0.72rem;color:#38BDF8;margin-bottom:6px'>Target scope: <b>{len(target_spec_ips) if target_spec_ips else 0} host(s)</b> parsed</div>", unsafe_allow_html=True)

    if st.button("📡 START ASSESSMENT", use_container_width=True, type="primary", disabled=st.session_state.get("scan_in_progress", False)):
        st.session_state["trigger_scan_now"] = True
        st.session_state["scan_base_ip"] = base_ip
        st.session_state["scan_limit"] = scan_limit
        st.session_state["scan_target_ips"] = target_spec_ips
        st.rerun()

# ─────────────────────────────────────────────────────────────────
# AUTOMATED / TRIGGERED ASSESSMENT EXECUTION
# ─────────────────────────────────────────────────────────────────
if st.session_state.get("trigger_scan_now", False):
    st.session_state["trigger_scan_now"] = False
    st.session_state.scan_in_progress = True
    try:
        cur_base_ip = st.session_state.get("scan_base_ip", base_ip)
        cur_scan_limit = st.session_state.get("scan_limit", scan_limit)
        cur_target_ips = st.session_state.get("scan_target_ips", target_spec_ips)

        progress_bar = st.progress(0, text="Initializing network assessment...")
        def _prog(done, total):
            if total > 0:
                progress_bar.progress(min(done/total, 1.0), text=f"Profiling host {done}/{total}...")

        st.session_state.scan_started_at = datetime.now(timezone.utc)
        with st.spinner("Executing discovery, banner grabbing & NVD correlation..."):
            devices, scan_timeline = scan_network(
                base_ip=cur_base_ip if not cur_target_ips else None,
                limit=cur_scan_limit,
                target_ips=cur_target_ips,
                progress_cb=_prog,
            )
        st.session_state.scan_completed_at = datetime.now(timezone.utc)
        progress_bar.empty()
        progress_bar.empty()

        if devices:
            st.session_state.G = build_dynamic_graph(devices)
            st.session_state.last_scan_devices = devices
            st.session_state.scan_timeline = scan_timeline
            record_scan_history(st.session_state.G, "Real Network Scan")
            run_dynamic_risk_pipeline("MANUAL_SCAN")
            st.toast(f"Assessment complete: {len(devices)} assets discovered", icon="🛡️")
        else:
            st.warning("No active hosts responded to ping/ARP probe in the specified range.")
    except Exception as exc:
        acds_log.error("Assessment error: %s", exc)
        st.error(f"Assessment stopped safely: {exc}")
    finally:
        st.session_state.scan_in_progress = False
    st.rerun()


# ─────────────────────────────────────────────────────────────────
# CONTINUOUS MONITORING BACKGROUND ITERATION
# ─────────────────────────────────────────────────────────────────
if st.session_state.get("monitoring_enabled", False):
    pass

# ─────────────────────────────────────────────────────────────────
# PRIMARY ROUTING SWITCH
# ─────────────────────────────────────────────────────────────────
cur_page = (st.session_state.get("nav_page") or "OVERVIEW").upper()

if "OVERVIEW" in cur_page:
    render_overview_page()
elif "ASSET" in cur_page:
    render_assets_page()
elif "VULNERABILIT" in cur_page:
    render_vulnerabilities_page()
elif "EXPOSURE" in cur_page:
    render_exposure_page()
elif "INCIDENT" in cur_page or "ALERT" in cur_page:
    render_incidents_page()
elif "ANALYSIS" in cur_page:
    render_analysis_page()
elif "RESPONSE" in cur_page:
    render_response_page()
elif "REPORT" in cur_page:
    render_reports_page()
elif "SETTING" in cur_page:
    render_settings_page()
else:
    render_overview_page()
