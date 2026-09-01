"""
ACDS Core Constants & Configuration Tables
Contains risk weights, scan ports, service maps, MITRE tags, MAC OUI vendor definitions,
and offline CVE fallback database.
"""

from typing import Dict, List, Set, Tuple

# Scanned TCP Ports
SCAN_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
]

PORT_SERVICE_MAP: Dict[int, str] = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB',
}

# Baseline exposure risk used when no version-specific CVE is found
SERVICE_BASELINE_RISK: Dict[str, float] = {
    'FTP': 0.55, 'SSH': 0.35, 'Telnet': 0.85, 'SMTP': 0.30, 'DNS': 0.25,
    'HTTP': 0.45, 'POP3': 0.40, 'RPC': 0.50, 'NetBIOS': 0.50, 'IMAP': 0.40,
    'HTTPS': 0.30, 'SMB': 0.60, 'MySQL': 0.65, 'RDP': 0.70,
    'PostgreSQL': 0.62, 'VNC': 0.68, 'Redis': 0.75, 'HTTP-Alt': 0.50,
    'HTTPS-Alt': 0.35, 'MongoDB': 0.70,
}

SERVICE_MITRE: Dict[str, Tuple[str, str]] = {
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

GENERIC_FIXES: Dict[str, str] = {
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

# MAC OUI Table for mobile/hardware detection
MOBILE_OUI_PREFIXES: Dict[str, str] = {
    # Apple
    'F0:18:98': 'Apple', '3C:15:C2': 'Apple', 'A4:5E:60': 'Apple',
    'DC:A9:04': 'Apple', '88:66:5A': 'Apple', '8C:85:90': 'Apple',
    'BC:92:6B': 'Apple', '40:B3:95': 'Apple', '6C:40:08': 'Apple',
    'AC:BC:32': 'Apple', '7C:6D:62': 'Apple', 'D4:E9:8A': 'Apple / Intel',
    '7C:6B:9C': 'Apple', 'F6:D0:23': 'Apple / Private MAC', 'B6:67:F3': 'Apple / Android',
    # Samsung
    '5C:0A:5B': 'Samsung', '8C:71:F8': 'Samsung', 'CC:07:AB': 'Samsung',
    'E8:50:8B': 'Samsung', '34:23:BA': 'Samsung', 'A0:21:95': 'Samsung',
    '64:B3:10': 'Samsung', '78:1F:DB': 'Samsung', 'D0:59:E4': 'Samsung',
    'E4:E3:3D': 'Samsung', 'C0:2E:5F': 'TP-Link / Network Gateway',
    # Xiaomi / Redmi / Poco
    '64:09:80': 'Xiaomi', '8C:BE:BE': 'Xiaomi', '28:6C:07': 'Xiaomi',
    '74:51:BA': 'Xiaomi', '50:8F:4C': 'Xiaomi', 'AC:C1:EE': 'Xiaomi',
    # Google (Pixel / Nest / Chromecast)
    '3C:5A:B4': 'Google', 'F4:F5:D8': 'Google', '94:EB:2C': 'Google',
    'A4:77:33': 'Google Nest', '54:60:09': 'Google Chromecast',
    # Huawei / Honor
    '00:E0:FC': 'Huawei', '48:7B:6B': 'Huawei', 'F8:01:13': 'Huawei',
    'C8:D7:19': 'Huawei',
    # OnePlus
    '94:65:2D': 'OnePlus', 'B4:0B:44': 'OnePlus',
    # Oppo / Vivo / Realme
    '40:4E:36': 'Oppo', '7C:64:56': 'Vivo', '50:32:75': 'Realme',
    # Motorola
    '88:0F:10': 'Motorola', 'B0:EC:71': 'Motorola',
    # Network Gateways & Routers (TP-Link, Netgear, D-Link, Asus, Cisco)
    '50:C7:BF': 'TP-Link', '14:CC:20': 'TP-Link', 'E8:48:B8': 'TP-Link',
    '98:DA:C4': 'TP-Link', 'B0:4E:26': 'TP-Link', '00:14:D1': 'Trendnet',
    '00:26:F2': 'Netgear', 'A0:04:60': 'Netgear', '20:4E:7F': 'Netgear',
    '00:1E:58': 'D-Link', '1C:7E:E5': 'D-Link', 'B8:A3:86': 'D-Link',
    '04:D4:C4': 'Asus', 'AC:22:0B': 'Asus', '00:1A:2B': 'Cisco',
    # Smart TVs / Media Streamers
    'B8:3E:59': 'Roku', 'DC:3A:5E': 'Raspberry Pi', 'B8:27:EB': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi', '00:04:20': 'Slim Devices / Smart Audio',
    '00:19:FB': 'LG Electronics (Smart TV)', 'A8:23:FE': 'LG Electronics',
    'F0:F5:64': 'Sony (PlayStation / Bravia)', '00:01:4A': 'Sony',
    '44:65:0D': 'Amazon (Echo / Fire TV)', 'FC:A6:67': 'Amazon',
    # IoT (Espressif, Tuya)
    '24:0A:C4': 'Espressif (ESP32/ESP8266)', '30:AE:A4': 'Espressif',
    '84:F3:EB': 'Espressif', 'A0:20:A6': 'Tuya Smart IoT',
    '68:57:2D': 'Tuya Smart IoT',
    # PC / Workstation NICs (Intel, Realtek, Dell, HP)
    '00:1A:A0': 'Dell', 'B8:85:84': 'Dell', '00:25:B3': 'HP',
    '00:1B:78': 'HP', '00:1F:16': 'Lenovo', '00:21:86': 'Lenovo',
    '00:1E:67': 'Intel', '3C:F8:62': 'Intel', '00:E0:4C': 'Realtek',
    '52:54:00': 'QEMU / KVM Virtual NIC', '08:00:27': 'Oracle VirtualBox',
    '00:0C:29': 'VMware', '00:50:56': 'VMware',
}

APPLE_OUI_PREFIXES: Set[str] = {k for k, v in MOBILE_OUI_PREFIXES.items() if 'Apple' in v}
PHONE_VENDORS: Set[str] = {'Apple', 'Samsung', 'Xiaomi', 'Google', 'Huawei', 'OnePlus', 'Oppo', 'Vivo', 'Realme', 'Motorola'}
ROUTER_VENDORS: Set[str] = {'TP-Link', 'Netgear', 'D-Link', 'Asus', 'Cisco', 'Trendnet', 'MikroTik', 'Ubiquiti'}
IOT_VENDORS: Set[str] = {'Espressif', 'Tuya', 'Raspberry Pi', 'Amazon', 'Google Nest'}
TV_VENDORS: Set[str] = {'Roku', 'LG Electronics', 'Sony', 'Samsung', 'Amazon'}

# Offline CVE Database Fallback Table
OFFLINE_CVE_FALLBACK: Dict[str, List[Dict]] = {
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

# Asset Risk Weights
RISK_WEIGHT_VULNERABILITY: float = 0.40
RISK_WEIGHT_SERVICE_EXPOSURE: float = 0.20
RISK_WEIGHT_SENSITIVE_SERVICES: float = 0.15
RISK_WEIGHT_CRITICALITY: float = 0.15
RISK_WEIGHT_NETWORK_EXPOSURE: float = 0.10

# Blast Radius Weights
BLAST_WEIGHT_SPREAD: float = 0.30
BLAST_WEIGHT_CRITICAL_IMPACT: float = 0.50
BLAST_WEIGHT_DEPTH: float = 0.20

# Overall ACDS Risk Synthesis Weights
OVERALL_WEIGHT_ASSET_RISK: float = 0.60
OVERALL_WEIGHT_BLAST_RADIUS: float = 0.40

# Caps & Limits
PORT_EXPOSURE_CAP: int = 10
SENSITIVE_PORT_CAP: int = 4
SENSITIVE_PORTS: Set[int] = {21, 23, 135, 139, 445, 3306, 3389, 5432, 5900, 6379, 27017}
SENSITIVE_PORT_LABELS: Dict[int, str] = {
    21: 'FTP', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 27017: 'MongoDB',
}

# Severity Classifications
SEVERITY_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
    (85, 'CRITICAL'), (65, 'HIGH'), (35, 'MEDIUM'), (0, 'LOW'),
)

CRITICALITY_LABELS: Dict[int, str] = {2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}
CRITICALITY_NORMALIZED: Dict[int, int] = {2: 0, 3: 33, 4: 67, 5: 100}

# Defense Action States
DEFENSE_STATE_RECOMMENDED: str = "RECOMMENDED"
DEFENSE_STATE_SELECTED: str = "SELECTED"
DEFENSE_STATE_APPLIED: str = "APPLIED TO SIMULATION MODEL"
