"""
ACDS Layered Network Discovery & Port Scanner Pipeline
Orchestrates active Layer-2 SendARP broadcast discovery, multi-threaded ICMP sweeps,
fast TCP probes, hostname resolution, port scanning, banner grabbing, and NIST NVD CVE correlation.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import platform
import re
import socket
import subprocess
from typing import Callable, Dict, List, Optional, Set, Tuple, Any

from acds.core.constants import (
    SCAN_PORTS,
    PORT_SERVICE_MAP,
    SERVICE_BASELINE_RISK,
    SERVICE_MITRE,
    GENERIC_FIXES,
)
from acds.discovery.arp import (
    ip_in_subnet,
    combined_arp_discovery,
    lookup_mac_windows,
)
from acds.discovery.icmp import icmp_sweep, ping_single
from acds.discovery.tcp_probe import quick_tcp_probe
from acds.discovery.subnet import detect_active_subnet, SubnetInfo
from acds.discovery.banners import grab_banner, parse_version_from_banner
from acds.discovery.fingerprint import (
    mac_vendor,
    infer_os_type,
    is_mobile_device,
    classify_device,
    format_device_display_name,
)
from acds.vulnerability.cve import (
    get_real_cves,
    detection_confidence_label,
)
from acds.vulnerability.risk import (
    calculate_vulnerability_score,
    calculate_service_exposure_score,
    calculate_sensitive_service_score,
)

# Global holder for last discovery diagnostics
LAST_DISCOVERY_STATS: Dict[str, Any] = {}


def _now_stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def get_local_ip() -> str:
    """Detect local subnet base prefix using active subnet detector."""
    sub = detect_active_subnet()
    parts = sub.local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}."


def get_local_system_context() -> Dict[str, Any]:
    """Retrieve host scanning environment details for self-host classification."""
    system = platform.system()
    ctx = {
        'scanner_system': system.lower(),
        'scanner_hostname': platform.node() or socket.gethostname(),
        'scanner_local_ips': set(),
    }
    try:
        host = ctx['scanner_hostname']
        if host:
            _, _, ips = socket.gethostbyname_ex(host)
            ctx['scanner_local_ips'].update(ips)
    except Exception:
        pass
    return ctx


def _clean_hostname(name: Optional[str], ip: str) -> Optional[str]:
    if not name:
        return None
    name = name.strip().rstrip('.')
    if name == ip or name.lower() in ('unknown', 'localhost'):
        return None
    return name


def resolve_hostname_dns(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return _clean_hostname(host, ip)
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_hostname_netbios(ip: str) -> Optional[str]:
    if platform.system() != "Windows":
        return None
    try:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=1.5)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if "<00>" in line and ("UNIQUE" in line.upper() or "GROUP" not in line.upper()):
                name = line.split("<")[0].strip()
                if name:
                    return _clean_hostname(name, ip)
    except Exception:
        pass
    return None


def resolve_hostname(ip: str) -> Optional[str]:
    """Resolve hostname using reverse DNS and NetBIOS."""
    name = resolve_hostname_dns(ip)
    if name:
        return name
    name = resolve_hostname_netbios(ip)
    if name:
        return name
    return None


def ping_ip(ip: str, system: str) -> Tuple[str, bool, Optional[int]]:
    """Legacy single IP ping wrapper."""
    return ping_single(ip, timeout_ms=600)


def scan_ports(ip: str, ports: List[int], timeout: float = 0.6) -> List[int]:
    """Perform fast multi-threaded port scan across targeted TCP ports."""
    open_ports = []

    def check_port(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_port, p) for p in ports]
        for f in as_completed(futures):
            pass

    return sorted(open_ports)


def detect_services_and_versions(
    ip: str,
    open_ports: List[int],
) -> Tuple[List[str], Dict[str, str], Dict[str, str]]:
    """Acquire service names, banners, and version strings for open ports."""
    services = []
    version_map = {}
    banner_map = {}

    for port in open_ports:
        service_name = PORT_SERVICE_MAP.get(port, f"Port-{port}")
        services.append(service_name)
        raw_banner, version_str = grab_banner(ip, port)
        if raw_banner:
            banner_map[service_name] = raw_banner
        if not version_str and raw_banner:
            version_str = parse_version_from_banner(service_name, raw_banner)
        if version_str:
            version_map[service_name] = version_str

    return services, version_map, banner_map


def assess_device_security(
    services: List[str],
    os_type: str,
    device_type: str,
    open_ports: List[int],
    role: str,
    version_map: Optional[Dict[str, str]] = None,
    ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Perform security assessment on host services, CVEs, and exposures."""
    version_map = version_map or {}
    cve_findings = []
    exposure_findings = []
    cve_sources_seen = set()
    fixes = []
    weaknesses = []
    access_vectors = []

    for svc in services:
        version_str = version_map.get(svc)
        port = next((p for p, s in PORT_SERVICE_MAP.items() if s == svc), None)
        port_num = port if port is not None else 0

        cves, source = get_real_cves(svc, version_str)
        if source != "none":
            cve_sources_seen.add(source)

        if cves:
            top_cve = cves[0]
            confidence = detection_confidence_label(source, bool(version_str))
            for c in cves[:3]:
                cve_findings.append({
                    'cve_id': c['id'],
                    'cvss': c['cvss'],
                    'severity': c.get('severity', 'Unknown'),
                    'service': svc,
                    'port': port_num,
                    'detected_product': svc,
                    'detected_version': version_str,
                    'summary': c.get('summary', ''),
                    'published': c.get('published', 'Unknown'),
                    'modified': c.get('modified', 'Unknown'),
                    'source': 'NIST NVD (live API)' if source == 'nvd_live' else 'Offline CVE Reference Table',
                    'detection_confidence': confidence,
                    'affected_product': svc,
                })
            weaknesses.append(f"{svc}: {top_cve['id']} (CVSS {top_cve['cvss']}) — {top_cve['summary'][:70]}")
            fixes.append(f"Patch {svc} on {ip or 'host'} to remediate {top_cve['id']}")
            access_vectors.append(f"{svc} vulnerability exploit ({top_cve['id']})")
        else:
            base_risk = SERVICE_BASELINE_RISK.get(svc, 0.30)
            exposure_findings.append({
                'service': svc,
                'port': port_num,
                'baseline_risk': base_risk,
                'reason': 'Service exposed without confirmed CVE finding',
            })
            if svc in GENERIC_FIXES:
                fixes.append(f"{svc}: {GENERIC_FIXES[svc]}")
            weaknesses.append(f"{svc} exposed on port {port_num} (baseline exposure risk)")
            access_vectors.append(f"{svc} brute force / credential attack")

    cve_source_label = (
        'nvd_live' if 'nvd_live' in cve_sources_seen
        else 'offline_table' if 'offline_table' in cve_sources_seen
        else 'none'
    )

    vuln_comp = calculate_vulnerability_score(cve_findings)
    if vuln_comp == 0.0 and exposure_findings:
        highest_base = max(e['baseline_risk'] for e in exposure_findings)
        vuln_comp = round(highest_base * 50.0, 1)

    svc_comp = calculate_service_exposure_score(len(open_ports))
    sens_comp, sens_detected = calculate_sensitive_service_score(open_ports)

    exposure_level = 'HIGH' if len(open_ports) >= 4 else 'MEDIUM' if len(open_ports) >= 2 else 'LOW'

    return {
        'vulnerability_component': vuln_comp,
        'service_component': svc_comp,
        'sensitive_component': sens_comp,
        'sensitive_detected': sens_detected,
        'cve_findings': cve_findings,
        'exposure_findings': exposure_findings,
        'cve_source': cve_source_label,
        'fixes': fixes,
        'weaknesses': weaknesses,
        'access_vectors': access_vectors,
        'exposure_level': exposure_level,
    }


def get_lateral_edges_for_target(open_ports: List[int]) -> List[Dict[str, Any]]:
    """Derive potential reachability and attack edges based on open target ports."""
    edges = []
    for port in open_ports:
        svc = PORT_SERVICE_MAP.get(port)
        if not svc:
            continue
        mitre_code, mitre_desc = SERVICE_MITRE.get(svc, ('T1021', f'Remote Service ({svc})'))
        base_prob = SERVICE_BASELINE_RISK.get(svc, 0.40)
        edges.append({
            'vector': f"{svc} attack (port {port})",
            'port': port,
            'mitre_code': mitre_code,
            'mitre_desc': mitre_desc,
            'success_prob': base_prob,
            'connection': f"{svc.lower()}/{port}",
        })

    if not edges:
        edges.append({
            'vector': 'LAN reachability / subnet spread',
            'port': 0,
            'mitre_code': 'T1078',
            'mitre_desc': 'Valid Accounts — LAN foothold spread',
            'success_prob': 0.35,
            'connection': 'lan/reachability',
        })
    return edges


def assign_role_from_services(services: List[str], os_type: str, device_type: str) -> str:
    """Assign asset role (Database, Server, Workstation, Gateway) from detected services and device type."""
    if device_type in ('Router / Gateway', 'Network Appliance'):
        return 'Gateway'
    if any(db in services for db in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        return 'Database'
    if any(w in services for w in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt', 'SMB', 'SSH', 'RDP', 'VNC', 'Telnet', 'SMTP', 'POP3', 'IMAP', 'DNS']):
        return 'Server'
    if device_type in ('Mobile Device', 'Tablet'):
        return 'Workstation'
    return 'Workstation'


def scan_network(
    base_ip: Optional[str] = None,
    limit: int = 254,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Tuple[List[Tuple], List[Dict[str, Any]]]:
    """
    Execute complete Layered LAN Discovery Architecture:
    1. Subnet & Interface Detection
    2. Active Layer-2 SendARP Broadcast Probing + ARP Cache Reconciliation
    3. Concurrent ICMP Echo Sweep & TTL Acquisition
    4. Fast TCP Port Probing
    5. Unified Host Deduplication & Discovery Evidence Tagging
    6. Hostname Resolution (Reverse DNS + NetBIOS)
    7. Targeted Port Scanning (across ALL discovered hosts)
    8. Service Banner Grabbing & Version Extraction
    9. Multi-Factor Device & OS Classification
    10. NIST NVD CVE Lookups & Baseline Security Assessment
    """
    global LAST_DISCOVERY_STATS

    timeline = []
    
    # ── LAYER 1: SUBNET & INTERFACE DETECTION ─────────────────────────────
    active_subnet: SubnetInfo = detect_active_subnet(fallback_prefix=base_ip or "192.168.1.")
    
    if base_ip is None:
        subnet_prefix = active_subnet.network_address.rsplit('.', 1)[0] + '.'
        usable_ips = active_subnet.usable_ips[:limit]
        gateway_ip = active_subnet.default_gateway
        cidr_str = active_subnet.cidr_notation
        iface_name = active_subnet.interface_name
    else:
        subnet_prefix = base_ip.rstrip('.') + '.'
        usable_ips = [f"{subnet_prefix}{i}" for i in range(1, limit + 1)]
        gateway_ip = f"{subnet_prefix}1"
        cidr_str = f"{subnet_prefix}0/24"
        iface_name = active_subnet.interface_name

    timeline.append({
        'timestamp': _now_stamp(),
        'event': 'Discovery started',
        'target': f"Interface: {iface_name} | Subnet: {cidr_str} | Gateway: {gateway_ip}",
        'status': 'Running',
    })

    # ── LAYER 2: ACTIVE ARP DISCOVERY (Layer-2 SendARP + Cache) ────────────
    timeline.append({
        'timestamp': _now_stamp(),
        'event': 'Active ARP probing started',
        'target': f"Scanning {len(usable_ips)} IPv4 targets via Layer-2 SendARP",
        'status': 'Running',
    })
    arp_map = combined_arp_discovery(usable_ips, subnet_prefix, max_workers=50)
    timeline.append({
        'timestamp': _now_stamp(),
        'event': 'ARP discovery completed',
        'target': f"{len(arp_map)} host(s) discovered via Layer-2 ARP",
        'status': 'Completed',
    })

    # ── LAYER 3: ICMP ECHO SWEEP ──────────────────────────────────────────
    timeline.append({
        'timestamp': _now_stamp(),
        'event': 'ICMP sweep started',
        'target': f"Probing {len(usable_ips)} IPv4 addresses",
        'status': 'Running',
    })
    icmp_map = icmp_sweep(usable_ips, timeout_ms=600, max_workers=50)
    timeline.append({
        'timestamp': _now_stamp(),
        'event': 'ICMP sweep completed',
        'target': f"{len(icmp_map)} host(s) responded to ICMP echo",
        'status': 'Completed',
    })

    # ── LAYER 4: FAST TCP PROBE ───────────────────────────────────────────
    # Quick sweep to catch non-ICMP hosts that didn't answer SendARP
    unconfirmed = [ip for ip in usable_ips if ip not in arp_map and ip not in icmp_map]
    tcp_responsive = quick_tcp_probe(unconfirmed, timeout=0.35, max_workers=30) if unconfirmed else set()

    # ── LAYER 5: UNIFIED DISCOVERY MERGE ──────────────────────────────────
    all_discovered_ips = set(arp_map.keys()) | set(icmp_map.keys()) | tcp_responsive
    candidate_ips = {ip for ip in all_discovered_ips if ip_in_subnet(ip, subnet_prefix)}

    total_discovered = len(candidate_ips)
    total_considered = len(usable_ips)

    arp_only = len(set(arp_map.keys()) - set(icmp_map.keys()))
    icmp_only = len(set(icmp_map.keys()) - set(arp_map.keys()))
    both_arp_icmp = len(set(arp_map.keys()) & set(icmp_map.keys()))

    timeline.append({
        'timestamp': _now_stamp(),
        'event': 'Discovery merged',
        'target': f"{total_discovered} unique device(s) found (ARP: {len(arp_map)}, ICMP: {len(icmp_map)}, Both: {both_arp_icmp})",
        'status': 'Completed',
    })

    local_ctx = get_local_system_context()

    # ── LAYER 6-10: ASSET ENRICHMENT & PROFILING ──────────────────────────
    def enrich_device(ip: str) -> Dict[str, Any]:
        mac = arp_map.get(ip)
        if not mac and platform.system() == "Windows":
            mac = lookup_mac_windows(ip)

        ttl = icmp_map.get(ip)
        is_gw = (ip == gateway_ip)
        
        # Discovery evidence list
        disc_ev = []
        if ip in arp_map:
            disc_ev.append("Layer-2 ARP")
        if ip in icmp_map:
            disc_ev.append("ICMP Echo")
        if ip in tcp_responsive:
            disc_ev.append("TCP Port Probe")
        if is_gw:
            disc_ev.append("Default Gateway")

        host_events = [{
            'timestamp': _now_stamp(),
            'event': 'Host discovered',
            'target': f"{ip} (Via: {', '.join(disc_ev) or 'LAN signal'})",
            'status': 'Discovered',
        }]

        if mac:
            host_events.append({
                'timestamp': _now_stamp(),
                'event': 'ARP/MAC resolved',
                'target': f"{ip} ({mac})",
                'status': 'Resolved',
            })

        hostname = resolve_hostname(ip)
        if hostname:
            host_events.append({
                'timestamp': _now_stamp(),
                'event': 'Hostname resolved',
                'target': f"{ip} -> {hostname}",
                'status': 'Resolved',
            })

        vendor = mac_vendor(mac)

        # ── LAYER 7: PORT SCANNING (ALL DISCOVERED HOSTS) ─────────────────
        try:
            open_ports = scan_ports(ip, SCAN_PORTS, timeout=0.5)
        except Exception as exc:
            open_ports = []
            host_events.append({
                'timestamp': _now_stamp(),
                'event': 'Port scan failed',
                'target': ip,
                'status': f'Unavailable ({type(exc).__name__})',
            })
        else:
            host_events.append({
                'timestamp': _now_stamp(),
                'event': 'Ports discovered',
                'target': ','.join(str(p) for p in open_ports) if open_ports else 'none (firewalled/client endpoint)',
                'status': 'Completed',
            })

        # ── LAYER 8: BANNERS & VERSIONS ──────────────────────────────────
        try:
            services, version_map, banner_map = detect_services_and_versions(ip, open_ports)
        except Exception as exc:
            services, version_map, banner_map = [], {}, {}
            host_events.append({
                'timestamp': _now_stamp(),
                'event': 'Banner grab failed',
                'target': ip,
                'status': f'Unavailable ({type(exc).__name__})',
            })
        else:
            if services:
                host_events.append({
                    'timestamp': _now_stamp(),
                    'event': 'Banners retrieved',
                    'target': ', '.join(services),
                    'status': 'Completed',
                })

        # ── LAYER 9: OS & DEVICE CLASSIFICATION ──────────────────────────
        try:
            os_result = infer_os_type(
                ip, ttl, hostname, mac, vendor, services,
                banner_map=banner_map, local_system_context=local_ctx,
            )
        except Exception as exc:
            os_result = {'os': 'unknown', 'confidence': 0.0, 'evidence': [f'OS inference error: {type(exc).__name__}']}

        is_mob = is_mobile_device(hostname, ip, mac)
        device_result = classify_device(
            hostname, os_result['os'], os_result['confidence'], is_mob,
            services, open_ports, mac=mac, is_gateway=is_gw,
            mac_vendor_name=vendor, ip=ip,
        )

        display_name = format_device_display_name(hostname, device_result['device_type'], ip)

        for svc in services:
            if version_map.get(svc):
                host_events.append({
                    'timestamp': _now_stamp(),
                    'event': 'NVD lookup completed',
                    'target': f"{svc} {version_map.get(svc)}",
                    'status': 'Completed',
                })

        return {
            'hostname': hostname,
            'os': os_result['os'],
            'os_confidence': os_result['confidence'],
            'os_evidence': os_result['evidence'] + [f"Discovery: {', '.join(disc_ev)}"],
            'is_mobile': is_mob,
            'mac': mac,
            'mac_vendor': vendor,
            'open_ports': open_ports,
            'services': services,
            'version_map': version_map,
            'banner_map': banner_map,
            'device_type': device_result['device_type'],
            'device_confidence': device_result['confidence'],
            'device_evidence': device_result['evidence'] + [f"Discovery: {', '.join(disc_ev)}"],
            'display_name': display_name,
            'events': host_events,
            'is_gateway': is_gw,
            'discovery_evidence': disc_ev,
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
                scan_had_errors = True
                timeline.append({
                    'timestamp': _now_stamp(),
                    'event': 'Host enrichment failed',
                    'target': ip,
                    'status': f'Unavailable ({type(exc).__name__})',
                })
            done += 1
            if progress_cb:
                progress_cb(done, total_discovered)

    # Diagnostic statistics
    hosts_with_ports = sum(1 for d in devices.values() if d.get('open_ports'))
    hosts_no_ports = sum(1 for d in devices.values() if not d.get('open_ports'))
    hosts_with_hostname = sum(1 for d in devices.values() if d.get('hostname'))

    LAST_DISCOVERY_STATS = {
        'interface': iface_name,
        'local_ip': active_subnet.local_ip,
        'subnet': cidr_str,
        'gateway': gateway_ip,
        'total_considered': total_considered,
        'total_discovered': total_discovered,
        'arp_discovered': len(arp_map),
        'icmp_discovered': len(icmp_map),
        'both_arp_and_icmp': both_arp_icmp,
        'arp_only': arp_only,
        'icmp_only': icmp_only,
        'hostname_resolved': hosts_with_hostname,
        'with_open_ports': hosts_with_ports,
        'no_open_ports': hosts_no_ports,
    }

    timeline.append({
        'timestamp': _now_stamp(),
        'event': 'Scan completed',
        'target': f"{total_discovered} device(s) profiled ({hosts_with_ports} with open ports, {hosts_no_ports} client/firewalled)",
        'status': 'Completed',
    })

    ordered = [
        (ip, d['hostname'], d['os'], d['os_confidence'], d['os_evidence'], d['is_mobile'],
         d['mac'], d['mac_vendor'], d['open_ports'], d['services'], d['version_map'],
         d['banner_map'], d['device_type'], d['display_name'], d['device_confidence'], d['device_evidence'])
        for ip, d in sorted(devices.items(), key=lambda item: tuple(map(int, item[0].split('.'))))
    ]
    return ordered, timeline


def get_last_discovery_stats() -> Dict[str, Any]:
    """Retrieve diagnostic statistics from the most recent real network scan."""
    global LAST_DISCOVERY_STATS
    return dict(LAST_DISCOVERY_STATS)
