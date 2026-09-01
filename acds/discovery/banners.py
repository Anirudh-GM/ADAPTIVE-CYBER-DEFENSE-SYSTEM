"""
ACDS Passive Service Banner Grabbing Engine
Safely acquires service version banners over standard TCP/TLS connections without exploitation.
"""

import re
import socket
import ssl
from typing import Optional, Tuple


def grab_banner(ip: str, port: int, timeout: float = 1.2) -> Tuple[Optional[str], Optional[str]]:
    """
    Safely connect to an open port and read service banner/header.
    Returns (raw_banner, parsed_version_string).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # HTTP / HTTP-Alt
            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                data = sock.recv(2048).decode(errors='ignore')
                m = re.search(r'Server:\s*(.+)', data, re.IGNORECASE)
                return data[:300], (m.group(1).strip() if m else None)

            # HTTPS / HTTPS-Alt
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


def parse_version_from_banner(service: str, banner: Optional[str]) -> Optional[str]:
    """Extract clean 'Product X.Y.Z' string from raw banner for CVE lookup."""
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
    return banner[:60]
