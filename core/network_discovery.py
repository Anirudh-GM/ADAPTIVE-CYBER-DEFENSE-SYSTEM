"""
ACDS Dynamic Network Environment & Interface Discovery Engine
─────────────────────────────────────────────────────────────────
Provides zero-hardcoding dynamic network detection:
- Active network interface / adapter
- Controller machine IP, hostname, OS
- Subnet mask, network CIDR (e.g. 192.168.0.0/24 or 172.16.0.0/21)
- Default gateway
- Dynamic target string parsing (Single IP, range, CIDR)
"""

import ipaddress
import platform
import re
import socket
import subprocess
from core.acds_logging import get_logger

log = get_logger(__name__)


def detect_network_environment():
    """
    Dynamically discover the local controller's active network environment.
    Never relies on hardcoded IP addresses or subnets.
    Returns a dict with:
        controller_ip, controller_hostname, os, system,
        adapter_name, subnet_cidr, base_ip_prefix, gateway_ip, netmask
    """
    system = platform.system()
    ctx = {
        'controller_ip': None,
        'controller_hostname': None,
        'os': {'Darwin': 'macos', 'Windows': 'windows', 'Linux': 'linux'}.get(system, 'unknown'),
        'system': system,
        'adapter_name': 'Default Interface',
        'subnet_cidr': None,
        'base_ip_prefix': None,
        'gateway_ip': None,
        'netmask': '255.255.255.0'
    }

    try:
        ctx['controller_hostname'] = socket.gethostname()
    except Exception:
        ctx['controller_hostname'] = 'localhost'

    # 1. Ask OS socket routing which local IP reaches outbound
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.5)
            s.connect(('8.8.8.8', 80))
            ctx['controller_ip'] = s.getsockname()[0]
    except Exception:
        try:
            ctx['controller_ip'] = socket.gethostbyname(socket.gethostname())
        except Exception:
            ctx['controller_ip'] = '127.0.0.1'

    # 2. OS-specific adapter and gateway probing
    if system == 'Windows':
        try:
            res = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=6)
            lines = res.stdout.splitlines()
            current_adapter = 'Unknown'
            adapters = {}
            for line in lines:
                sline = line.strip()
                if ('adapter' in line.lower()) and line.endswith(':'):
                    current_adapter = line.strip().rstrip(':')
                    adapters[current_adapter] = {'ip': None, 'mask': '255.255.255.0', 'gateway': None}
                elif current_adapter in adapters:
                    if 'Media State' in sline and 'disconnected' in sline.lower():
                        adapters[current_adapter]['ip'] = None
                        adapters[current_adapter]['gateway'] = None
                    elif 'IPv4 Address' in sline or 'ipv4' in sline.lower():
                        parts = sline.split(':')
                        if len(parts) > 1:
                            ip_val = parts[-1].split('(')[0].strip()
                            adapters[current_adapter]['ip'] = ip_val
                    elif 'Subnet Mask' in sline:
                        parts = sline.split(':')
                        if len(parts) > 1:
                            adapters[current_adapter]['mask'] = parts[-1].strip()
                    elif 'Default Gateway' in sline:
                        parts = sline.split(':')
                        if len(parts) > 1:
                            gw = parts[-1].strip()
                            if gw and gw != '(none)' and not gw.startswith('::'):
                                adapters[current_adapter]['gateway'] = gw

            best_adapter = None
            for ad_name, ad_data in adapters.items():
                if ad_data.get('ip') == ctx['controller_ip']:
                    best_adapter = (ad_name, ad_data)
                    break
                if ad_data.get('gateway') and not best_adapter and ad_data.get('ip'):
                    best_adapter = (ad_name, ad_data)

            if best_adapter:
                ad_name, ad_data = best_adapter
                ctx['adapter_name'] = ad_name
                if not ctx['controller_ip'] and ad_data.get('ip'):
                    ctx['controller_ip'] = ad_data['ip']
                if ad_data.get('gateway'):
                    ctx['gateway_ip'] = ad_data['gateway']
                if ad_data.get('mask'):
                    ctx['netmask'] = ad_data['mask']
        except Exception as exc:
            log.debug("ipconfig parsing failed: %s", exc)
    else:
        # Linux / macOS
        try:
            cmd = ["ifconfig"] if system == "Darwin" else ["ip", "-4", "addr", "show"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            for line in res.stdout.splitlines():
                sline = line.strip()
                if 'inet ' in sline and '127.0.0.1' not in sline:
                    # e.g. inet 192.168.1.50/24 or inet 192.168.1.50 netmask 255.255.255.0
                    parts = sline.split()
                    for idx, p in enumerate(parts):
                        if p == 'inet' and idx + 1 < len(parts):
                            val = parts[idx + 1]
                            if '/' in val:
                                ip_p, mask_p = val.split('/', 1)
                                if not ctx['controller_ip']:
                                    ctx['controller_ip'] = ip_p
                                try:
                                    iface = ipaddress.IPv4Interface(val)
                                    ctx['subnet_cidr'] = str(iface.network)
                                    ctx['netmask'] = str(iface.netmask)
                                except Exception:
                                    pass
        except Exception as exc:
            log.debug("unix ifconfig/ip parsing failed: %s", exc)

        # Gateway on Unix
        try:
            route_res = subprocess.run(["netstat", "-rn"] if system == "Darwin" else ["ip", "route"],
                                       capture_output=True, text=True, timeout=5)
            for rline in route_res.stdout.splitlines():
                if 'default' in rline or '0.0.0.0' in rline:
                    tokens = rline.split()
                    for t in tokens:
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', t) and t != '0.0.0.0':
                            ctx['gateway_ip'] = t
                            break
                    if ctx['gateway_ip']:
                        break
        except Exception:
            pass

    # Calculate Subnet CIDR & Base IP Prefix
    if ctx['controller_ip'] and ctx['controller_ip'] != '127.0.0.1':
        if not ctx['subnet_cidr']:
            try:
                iface = ipaddress.IPv4Interface(f"{ctx['controller_ip']}/{ctx['netmask']}")
                ctx['subnet_cidr'] = str(iface.network)
            except Exception:
                octs = ctx['controller_ip'].split('.')
                if len(octs) == 4:
                    ctx['subnet_cidr'] = f"{octs[0]}.{octs[1]}.{octs[2]}.0/24"

        octs = ctx['controller_ip'].split('.')
        if len(octs) == 4:
            ctx['base_ip_prefix'] = f"{octs[0]}.{octs[1]}.{octs[2]}."

    if not ctx['gateway_ip'] and ctx['base_ip_prefix']:
        ctx['gateway_ip'] = f"{ctx['base_ip_prefix']}1"

    if not ctx['base_ip_prefix']:
        ctx['base_ip_prefix'] = "192.168.1."
    if not ctx['subnet_cidr']:
        ctx['subnet_cidr'] = f"{ctx['base_ip_prefix']}0/24"
    if not ctx['controller_ip']:
        ctx['controller_ip'] = f"{ctx['base_ip_prefix']}100"

    return ctx


def parse_target_ips(target_input, base_prefix=None):
    """
    Parse a target specification into a list of IPv4 strings.
    Supports:
      - Single IP: '192.168.0.101' or '10.0.0.5'
      - Comma/space-separated list: '192.168.0.101, 192.168.0.102'
      - CIDR notation: '192.168.0.0/28' (capped at 256 hosts for safety)
      - Host range: '1-30' or '100-110' (combined with base_prefix)
      - Base prefix shorthand: '192.168.0.' -> scans 1..254
    """
    if not target_input or not str(target_input).strip():
        return []

    target_str = str(target_input).strip()
    result_ips = []

    # 1. CIDR notation
    if '/' in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            # Cap at 256 hosts for safety in UI
            for idx, host in enumerate(net.hosts()):
                if idx >= 256:
                    break
                result_ips.append(str(host))
            return result_ips
        except ValueError:
            pass

    # 2. Comma or whitespace separated IPs
    raw_tokens = [t.strip() for t in re.split(r'[,\s]+', target_str) if t.strip()]
    
    # Check if all tokens are valid IPv4
    is_all_ips = True
    for token in raw_tokens:
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', token):
            result_ips.append(token)
        elif '-' in token and base_prefix:
            # Range e.g. 1-20
            parts = token.split('-', 1)
            try:
                start_h = int(parts[0])
                end_h = int(parts[1])
                for h in range(start_h, end_h + 1):
                    if 1 <= h <= 254:
                        result_ips.append(f"{base_prefix}{h}")
            except ValueError:
                is_all_ips = False
        elif token.endswith('.') and token.count('.') == 3:
            # Base prefix like "192.168.0."
            for h in range(1, 255):
                result_ips.append(f"{token}{h}")
        else:
            is_all_ips = False

    return sorted(list(dict.fromkeys(result_ips)), key=lambda x: tuple(map(int, x.split('.'))) if x.count('.') == 3 else x)
