"""
ACDS Real-Time Protocol Device Fingerprinting Engine
─────────────────────────────────────────────────────────────────
Active, non-destructive protocol discovery and device fingerprinting:
  1. NetBIOS Node Status Queries (UDP 137) -> Computer Name, Workgroup, Domain
  2. mDNS / Bonjour Service Queries (UDP 5353) -> Apple/Android/Cast/Workstation signatures
  3. SSDP / UPnP M-SEARCH Queries (UDP 1900) -> Device Manufacturer & Model
  4. MAC Randomization / Locally Administered Address (LAA) Intelligence
  5. Aggregated Evidence-Based Device Classification
"""

import re
import socket
import struct
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from core.acds_logging import get_logger

log = get_logger(__name__)

# Extended Mobile & Device Vendors
EXPANDED_OUI_MAP = {
    # Apple
    "00:17:F2": "Apple", "00:1E:C2": "Apple", "00:26:B0": "Apple", "00:88:65": "Apple",
    "04:0C:CE": "Apple", "08:66:98": "Apple", "0C:74:C2": "Apple", "10:93:E9": "Apple",
    "18:AF:61": "Apple", "20:76:8F": "Apple", "28:CF:E9": "Apple", "30:90:AB": "Apple",
    "38:CA:DA": "Apple", "40:6C:8F": "Apple", "48:60:5F": "Apple", "50:BC:96": "Apple",
    "58:55:CA": "Apple", "60:F8:1D": "Apple", "64:20:0C": "Apple", "70:3E:AC": "Apple",
    "78:7B:8A": "Apple", "80:49:71": "Apple", "88:66:A5": "Apple", "90:72:40": "Apple",
    "98:01:A7": "Apple", "A4:C3:61": "Apple", "AC:87:A3": "Apple", "B0:34:95": "Apple",
    "B8:78:2E": "Apple", "C0:84:7A": "Apple", "C8:3C:85": "Apple", "D0:25:98": "Apple",
    "D8:30:62": "Apple", "E0:B9:BA": "Apple", "E8:80:2E": "Apple", "F0:18:98": "Apple",
    "F4:F1:5A": "Apple", "F8:FF:C2": "Apple", "FC:25:3F": "Apple",
    # Samsung
    "00:07:AB": "Samsung", "00:12:47": "Samsung", "00:15:99": "Samsung", "00:17:C9": "Samsung",
    "00:21:4C": "Samsung", "08:37:3D": "Samsung", "14:49:E0": "Samsung", "24:4B:03": "Samsung",
    "30:C7:50": "Samsung", "34:23:BA": "Samsung", "44:78:3E": "Samsung", "50:85:69": "Samsung",
    "5C:0A:5B": "Samsung", "68:EB:AE": "Samsung", "78:47:1D": "Samsung", "84:25:19": "Samsung",
    "94:01:C2": "Samsung", "A0:0B:BA": "Samsung", "AC:5F:3E": "Samsung", "B4:07:F9": "Samsung",
    "C4:42:02": "Samsung", "D0:17:6A": "Samsung", "E4:58:B8": "Samsung", "FC:A1:3E": "Samsung",
    # Google / Pixel
    "3C:5A:37": "Google", "54:60:09": "Google", "94:EB:CD": "Google", "A4:77:33": "Google",
    "D8:6C:63": "Google", "F4:F5:D8": "Google", "F8:8F:C2": "Google", "58:CB:52": "Google",
    # Xiaomi / Redmi / Poco
    "00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "14:F6:5A": "Xiaomi", "18:59:36": "Xiaomi",
    "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi", "50:64:2B": "Xiaomi", "64:09:80": "Xiaomi",
    "78:02:F8": "Xiaomi", "8C:BE:BE": "Xiaomi", "9C:28:40": "Xiaomi", "AC:C1:EE": "Xiaomi",
    # OnePlus / Oppo / Vivo / Realme
    "94:65:2D": "OnePlus", "A0:93:47": "OnePlus", "00:22:F4": "Oppo", "40:4E:34": "Oppo",
    "64:1C:67": "Oppo", "88:C9:D0": "Vivo", "DC:72:9B": "Vivo", "70:2C:1F": "Realme",
    # Network / IoT / Laptops
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "24:0A:C4": "Espressif (IoT)", "30:AE:A4": "Espressif (IoT)", "84:CC:A8": "Espressif (IoT)",
    "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:15:5D": "Microsoft Hyper-V",
    "00:1A:2B": "Intel", "00:1E:67": "Intel", "3C:F8:62": "Intel", "80:86:F2": "Intel",
}


def is_randomized_mac(mac: str) -> bool:
    """
    Check if a MAC address is a Locally Administered Address (LAA).
    According to IEEE 802, bit 1 of the most significant byte indicates LAA:
    Second hex character will be 2, 6, A, or E (e.g. 62:7C:..., DA:..., 3E:...).
    Mobile OSs (iOS, Android 10+) use LAAs for Wi-Fi privacy.
    """
    if not mac or len(mac) < 2:
        return False
    clean_mac = mac.replace(":", "").replace("-", "").strip()
    if len(clean_mac) < 2:
        return False
    try:
        first_byte = int(clean_mac[:2], 16)
        # Bit 1 set = locally administered (randomized)
        return bool(first_byte & 0x02)
    except ValueError:
        return False


def resolve_mac_vendor_extended(mac: str) -> dict:
    """
    Extended MAC vendor resolution with randomized MAC recognition.
    """
    if not mac:
        return {"vendor": None, "is_randomized": False, "note": "No MAC provided"}

    is_rand = is_randomized_mac(mac)
    prefix = mac.upper()[:8].replace("-", ":")
    vendor = EXPANDED_OUI_MAP.get(prefix)

    if vendor:
        return {
            "vendor": vendor,
            "is_randomized": False,
            "note": f"IEEE OUI resolved to {vendor}"
        }

    if is_rand:
        return {
            "vendor": "Private / Randomized MAC",
            "is_randomized": True,
            "note": "Locally Administered Address (Privacy MAC typical of iOS/Android/Windows 11)"
        }

    return {"vendor": None, "is_randomized": False, "note": "Unregistered IEEE OUI"}


# ─────────────────────────────────────────────────────────────────
# 1. NETBIOS NAME SERVICE QUERY (UDP 137)
# ─────────────────────────────────────────────────────────────────

def query_netbios_name(ip: str, timeout: float = 0.6) -> dict:
    """
    Safely queries NetBIOS Name Service (port 137) using a standard Node Status query.
    Extracts computer name, active workgroup, and registered MAC.
    """
    res = {
        "hostname": None,
        "workgroup": None,
        "is_server": False,
        "netbios_mac": None,
        "success": False
    }

    # NetBIOS Name Service Node Status Query packet (RFC 1002)
    # Header: Transaction ID 0x1337, Flags 0x0000, 1 Question, 0 Answers
    # Query: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (wildcard '*') Node Status (0x0021), IN (0x0001)
    packet = (
        b"\x13\x37"                          # Transaction ID
        b"\x00\x00"                          # Flags: Broadcast query
        b"\x00\x01\x00\x00\x00\x00\x00\x00"  # Questions: 1, Answer RRs: 0, Authority: 0, Additional: 0
        b"\x20"                              # Length of name: 32 bytes
        b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Encoded '*'
        b"\x00"                              # Null terminator
        b"\x00\x21"                          # Type: NBSTAT (Node status)
        b"\x00\x01"                          # Class: IN
    )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, 137))
            data, _ = sock.recvfrom(1024)

            if len(data) > 56:
                num_names = data[56]
                offset = 57
                names = []
                for _ in range(num_names):
                    if offset + 18 <= len(data):
                        name_bytes = data[offset:offset+15].rstrip()
                        name_type = data[offset+15]
                        flags = struct.unpack(">H", data[offset+16:offset+18])[0]
                        is_group = bool(flags & 0x8000)

                        try:
                            decoded_name = name_bytes.decode("ascii", errors="ignore").strip()
                            if decoded_name:
                                names.append((decoded_name, name_type, is_group))
                        except Exception:
                            pass
                        offset += 18

                for name, ntype, is_group in names:
                    if not is_group and ntype == 0x00 and not res["hostname"]:
                        res["hostname"] = name
                    elif is_group and ntype == 0x00 and not res["workgroup"]:
                        res["workgroup"] = name
                    elif ntype == 0x20:
                        res["is_server"] = True
                        if not res["hostname"]:
                            res["hostname"] = name

                if offset + 6 <= len(data):
                    raw_mac = data[offset:offset+6]
                    res["netbios_mac"] = ":".join(f"{b:02X}" for b in raw_mac)

                if res["hostname"]:
                    res["success"] = True
    except Exception:
        pass

    return res


# ─────────────────────────────────────────────────────────────────
# 2. mDNS / BONJOUR SERVICE PROBING (UDP 5353)
# ─────────────────────────────────────────────────────────────────

def _build_mdns_query(service_name: str) -> bytes:
    """Helper to build a unicast DNS PTR query packet for mDNS."""
    # Transaction ID: 0x0000, Flags: 0x0000 (Standard Query), Questions: 1
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b""
    for part in service_name.split("."):
        if part:
            bpart = part.encode("utf-8")
            qname += bytes([len(bpart)]) + bpart
    qname += b"\x00"
    # Type: PTR (0x000C), Class: IN (0x0001)
    qtype_class = b"\x00\x0c\x00\x01"
    return header + qname + qtype_class


def query_mdns_services(ip: str, timeout: float = 0.8) -> dict:
    """
    Safely probes mDNS (UDP 5353) on target host for service announcements.
    Detects Apple devices, Google Cast/Android, AirPlay, and friendly hostnames.
    """
    res = {
        "services": [],
        "device_hint": None,
        "friendly_name": None,
        "is_apple": False,
        "is_android_cast": False,
        "is_spotify_speaker": False,
        "success": False
    }

    # Probed signature PTRs
    probe_services = [
        "_apple-mobdev2._tcp.local",
        "_airplay._tcp.local",
        "_googlecast._tcp.local",
        "_spotify-connect._tcp.local",
        "_workstation._tcp.local",
        "_companion-link._tcp.local",
        "_device-info._tcp.local"
    ]

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            for srv in probe_services:
                pkt = _build_mdns_query(srv)
                try:
                    sock.sendto(pkt, (ip, 5353))
                except Exception:
                    pass

            # Read responses with short timeout
            sock.settimeout(min(timeout, 0.4))
            for _ in range(3):
                try:
                    data, _ = sock.recvfrom(2048)
                    if data:
                        raw_str = data.decode("latin1", errors="ignore")
                        for srv in probe_services:
                            srv_tag = srv.split(".")[0]
                            if srv_tag in raw_str and srv_tag not in res["services"]:
                                res["services"].append(srv_tag)

                        if "_apple-mobdev2" in raw_str or "_airplay" in raw_str or "_companion-link" in raw_str:
                            res["is_apple"] = True
                            res["device_hint"] = "Apple iOS / macOS Device"
                        if "_googlecast" in raw_str:
                            res["is_android_cast"] = True
                            res["device_hint"] = "Android / Google Cast Device"
                        if "_spotify-connect" in raw_str:
                            res["is_spotify_speaker"] = True

                        # Extract potential friendly name in TXT/PTR payload
                        # e.g. "fn=Anirudh iPhone" or "model=iPhone14,2"
                        fn_match = re.search(r'fn=([^\x00\r\n]{3,30})', raw_str)
                        if fn_match:
                            res["friendly_name"] = fn_match.group(1).strip()
                        md_match = re.search(r'model=([^\x00\r\n]{3,30})', raw_str)
                        if md_match and not res["device_hint"]:
                            res["device_hint"] = f"Model {md_match.group(1).strip()}"

                        res["success"] = bool(res["services"] or res["device_hint"])
                except socket.timeout:
                    break
                except Exception:
                    break
    except Exception:
        pass

    return res


# ─────────────────────────────────────────────────────────────────
# 3. SSDP / UPnP M-SEARCH QUERY (UDP 1900)
# ─────────────────────────────────────────────────────────────────

def query_ssdp_device_info(ip: str, timeout: float = 0.8) -> dict:
    """
    Safely sends unicast SSDP M-SEARCH on UDP 1900 to discover device model,
    manufacturer, and friendly name.
    """
    res = {
        "server_banner": None,
        "location": None,
        "manufacturer": None,
        "model_name": None,
        "friendly_name": None,
        "device_type": None,
        "success": False
    }

    msearch_pkt = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(msearch_pkt, (ip, 1900))
            data, _ = sock.recvfrom(2048)

            raw_resp = data.decode("utf-8", errors="ignore")
            lines = raw_resp.split("\r\n")

            for line in lines:
                if line.lower().startswith("server:"):
                    res["server_banner"] = line.split(":", 1)[1].strip()
                elif line.lower().startswith("location:"):
                    res["location"] = line.split(":", 1)[1].strip()

            if res["server_banner"]:
                srv_lower = res["server_banner"].lower()
                if "android" in srv_lower:
                    res["device_type"] = "Android Device"
                elif "ios" in srv_lower or "iphone" in srv_lower or "darwin" in srv_lower:
                    res["device_type"] = "Apple Device"
                elif "windows" in srv_lower:
                    res["device_type"] = "Windows Host"
                elif "linux" in srv_lower:
                    res["device_type"] = "Linux Host"

            # If location XML URL is available, attempt to parse description
            if res["location"] and res["location"].startswith("http"):
                try:
                    req = urllib.request.Request(res["location"], headers={"User-Agent": "ACDS-Scanner"})
                    with urllib.request.urlopen(req, timeout=0.8) as resp:
                        xml_content = resp.read().decode("utf-8", errors="ignore")
                        man_m = re.search(r'<manufacturer>(.*?)</manufacturer>', xml_content, re.I)
                        if man_m:
                            res["manufacturer"] = man_m.group(1).strip()
                        mod_m = re.search(r'<modelName>(.*?)</modelName>', xml_content, re.I)
                        if mod_m:
                            res["model_name"] = mod_m.group(1).strip()
                        fn_m = re.search(r'<friendlyName>(.*?)</friendlyName>', xml_content, re.I)
                        if fn_m:
                            res["friendly_name"] = fn_m.group(1).strip()
                except Exception:
                    pass

            res["success"] = bool(res["server_banner"] or res["model_name"] or res["friendly_name"])
    except Exception:
        pass

    return res


# ─────────────────────────────────────────────────────────────────
# 4. AGGREGATED REAL-TIME FINGERPRINTING ENGINE
# ─────────────────────────────────────────────────────────────────

def fingerprint_asset_realtime(ip: str, mac: str = None, current_hostname: str = None,
                               open_ports: list = None, services: list = None) -> dict:
    """
    Executes multi-protocol active fingerprinting against a live target asset.
    Returns rich, evidence-based device classification, verified hostname,
    inferred OS, and concrete evidence list.
    """
    open_ports = open_ports or []
    services = services or []
    evidence = []

    # 1. MAC Analysis
    mac_info = resolve_mac_vendor_extended(mac)
    vendor = mac_info.get("vendor")
    is_rand_mac = mac_info.get("is_randomized", False)

    if vendor and not is_rand_mac:
        evidence.append(f"MAC vendor resolved: {vendor}")
    elif is_rand_mac:
        evidence.append("Randomized/Private MAC detected (IEEE LAA — typical of iOS/Android/Win11 Wi-Fi privacy)")

    # 2. Parallel Protocol Probing (NetBIOS, mDNS, SSDP)
    netbios_res = {}
    mdns_res = {}
    ssdp_res = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_netbios = executor.submit(query_netbios_name, ip, 0.6)
        f_mdns = executor.submit(query_mdns_services, ip, 0.8)
        f_ssdp = executor.submit(query_ssdp_device_info, ip, 0.8)

        try:
            netbios_res = f_netbios.result()
        except Exception:
            pass
        try:
            mdns_res = f_mdns.result()
        except Exception:
            pass
        try:
            ssdp_res = f_ssdp.result()
        except Exception:
            pass

    # Process NetBIOS
    resolved_hostname = current_hostname
    if netbios_res.get("success"):
        nb_name = netbios_res.get("hostname")
        nb_wg = netbios_res.get("workgroup")
        if nb_name:
            resolved_hostname = nb_name
            evidence.append(f"NetBIOS query returned host name '{nb_name}' (Workgroup: {nb_wg or 'WORKGROUP'})")
        if netbios_res.get("is_server"):
            evidence.append("NetBIOS announced file/print server service flags")

    # Process mDNS
    if mdns_res.get("success"):
        if mdns_res.get("friendly_name"):
            resolved_hostname = mdns_res["friendly_name"]
            evidence.append(f"mDNS announced friendly device name: '{mdns_res['friendly_name']}'")
        if mdns_res.get("device_hint"):
            evidence.append(f"mDNS service probe: {mdns_res['device_hint']}")
        if mdns_res.get("services"):
            evidence.append(f"mDNS active services: {', '.join(mdns_res['services'])}")

    # Process SSDP
    if ssdp_res.get("success"):
        if ssdp_res.get("friendly_name"):
            evidence.append(f"UPnP announced friendly name: '{ssdp_res['friendly_name']}'")
        if ssdp_res.get("model_name"):
            evidence.append(f"UPnP model name: {ssdp_res['model_name']} ({ssdp_res.get('manufacturer', 'Unknown vendor')})")
        elif ssdp_res.get("server_banner"):
            evidence.append(f"SSDP server header: {ssdp_res['server_banner']}")

    # ─────────────────────────────────────────────────────────────
    # DECISION CLASSIFICATION
    # ─────────────────────────────────────────────────────────────
    inferred_device = "Unknown"
    inferred_os = "unknown"
    confidence = 0.20
    is_mobile = False

    hl = (resolved_hostname or "").lower()

    # Rule A: Concrete mDNS / SSDP Mobile Signatures
    if mdns_res.get("is_apple") or "iphone" in hl or "ipad" in hl:
        inferred_device = "Mobile Device (Apple iOS)" if ("iphone" in hl or "mobdev" in str(mdns_res.get("services"))) else "Mac Computer"
        inferred_os = "ios" if "Mobile" in inferred_device else "macos"
        confidence = 0.85
        is_mobile = ("Mobile" in inferred_device)

    elif mdns_res.get("is_android_cast") or "android" in hl or (ssdp_res.get("device_type") == "Android Device"):
        inferred_device = "Mobile Device (Android)"
        inferred_os = "android"
        confidence = 0.85
        is_mobile = True

    # Rule B: NetBIOS Windows Confirmation
    elif netbios_res.get("success"):
        inferred_device = "Windows Server" if (netbios_res.get("is_server") or 445 in open_ports) else "Windows Workstation"
        inferred_os = "windows"
        confidence = 0.90

    # Rule C: MAC Vendor + Randomized MAC Heuristics
    elif vendor in ("Apple", "Samsung", "Xiaomi", "OnePlus", "Oppo", "Vivo", "Realme", "Google"):
        inferred_device = "Mobile Device"
        inferred_os = "ios" if vendor == "Apple" else "android"
        confidence = 0.75
        is_mobile = True
        evidence.append(f"Hardware manufacturer {vendor} is a primary mobile vendor")

    elif is_rand_mac and (53 in open_ports or len(open_ports) <= 2):
        # Unnamed host with randomized privacy MAC + hotspot/DNS or minimal ports
        inferred_device = "Mobile Device (Likely / Privacy MAC)"
        inferred_os = "unknown"
        confidence = 0.50
        is_mobile = True
        evidence.append("Combination of randomized MAC address and minimal port footprint is consistent with a smartphone")

    elif "router" in hl or "gateway" in hl or 53 in open_ports and 80 in open_ports:
        inferred_device = "Network Device / Gateway"
        inferred_os = "linux"
        confidence = 0.65

    elif 445 in open_ports or 3389 in open_ports:
        inferred_device = "Windows Host"
        inferred_os = "windows"
        confidence = 0.70

    elif 22 in open_ports or 80 in open_ports:
        inferred_device = "Linux Server / Host"
        inferred_os = "linux"
        confidence = 0.65

    return {
        "ip": ip,
        "mac": mac,
        "resolved_hostname": resolved_hostname,
        "inferred_device": inferred_device,
        "inferred_os": inferred_os,
        "confidence": confidence,
        "is_mobile": is_mobile,
        "is_randomized_mac": is_rand_mac,
        "mac_vendor": vendor,
        "evidence": evidence,
        "netbios": netbios_res,
        "mdns": mdns_res,
        "ssdp": ssdp_res,
    }


def batch_fingerprint_assets(asset_list: list, max_workers: int = 4) -> dict:
    """
    Fingerprints a list of asset dicts concurrently.
    Each item in asset_list should have at least 'ip', optionally 'mac', 'hostname', 'open_ports'.
    Returns dict keyed by ip or asset_id.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for a in asset_list:
            ip = a.get("ip")
            if ip:
                mac = a.get("mac")
                host = a.get("hostname")
                ports = a.get("open_ports", [])
                srvs = a.get("services", [])
                future_map[executor.submit(fingerprint_asset_realtime, ip, mac, host, ports, srvs)] = a

        for f in future_map:
            try:
                res = f.result()
                ip = res["ip"]
                orig = future_map[f]
                asset_key = orig.get("asset_id") or ip
                results[asset_key] = res
            except Exception as exc:
                log.debug("Fingerprint worker error: %s", exc)

    return results
