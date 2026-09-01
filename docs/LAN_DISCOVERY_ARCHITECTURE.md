# ACDS Layered LAN Device Discovery Architecture

## Executive Overview

The **Adaptive Cyber Defense System (ACDS)** implements a 10-layer, multi-signal network discovery and profiling architecture engineered to discover all active, authorized devices on a local subnet—including mobile phones, smart TVs, IoT hardware, network appliances, and workstations that drop ICMP echo requests or expose no open server ports.

---

## 1. Root Cause Analysis: Why Devices Were Previously Missed

| Root Cause | Technical Failure Mode in Previous Implementation | ACDS Layered Solution |
|---|---|---|
| **Passive ARP Cache Reliance** | `read_arp_map` only executed `arp -a`. On Windows, `arp -a` only contains hosts that the scanner recently communicated with. Silent devices on the subnet were completely omitted. | **Active Layer-2 SendARP Broadcast**: Uses `ctypes.windll.iphlpapi.SendARP` to actively query all 254 subnet hosts at Layer 2. |
| **Ping-Dependent Port Scanning** | `scanner.py` had `open_ports = scan_ports(ip, SCAN_PORTS) if ip in ping_results else []`. Any device blocking ICMP was denied port scanning and banner extraction! | **Decoupled Discovery from Profiling**: Every host discovered via ARP, ICMP, or TCP probe is fully scanned and profiled. |
| **Subnet Truncation** | Preset range slider defaulted to `100`, ignoring devices located between `.101` and `.254`. | **Full Subnet Auto-Sizing**: Automatically binds to detected subnet mask (`/24`) with default scan limit of 254. |
| **Firewalled / 0-Port Discard** | Client devices (smartphones, tablets, smart TVs) often expose 0 standard server ports and were misclassified or discarded. | **First-Class 0-Port Asset Modeling**: Devices without open ports remain full assets with explicit evidence (`Layer-2 ARP • Client Endpoint`). |

---

## 2. The 10-Layer Discovery Pipeline

```
[1] SUBNET & INTERFACE DETECTION (ipconfig / socket routing / CIDR validation)
    ↓
[2] ACTIVE LAYER-2 ARP DISCOVERY (ctypes.windll.iphlpapi.SendARP) + SYSTEM ARP CACHE
    ↓
[3] CONCURRENT ICMP SWEEP (Ping & TTL extraction for OS inference)
    ↓
[4] FAST TCP PROBE (Direct connection check across key LAN ports)
    ↓
[5] UNIFIED DISCOVERY MERGE (Deduplicate by IP & MAC, tag discovery evidence)
    ↓
[6] SAFE HOSTNAME RESOLUTION (Reverse DNS + NetBIOS)
    ↓
[7] TARGETED MULTI-THREADED PORT SCANNING (Across ALL discovered hosts)
    ↓
[8] BANNER GRABBING & VERSION EXTRACTION (HTTP, SSH, FTP, MySQL, SMB, RPC)
    ↓
[9] MULTI-FACTOR DEVICE & OS CLASSIFICATION (Gateway, Mobile, Smart TV, IoT, Server)
    ↓
[10] SECURITY & CVE EXPOSURE ASSESSMENT (NIST NVD live/offline correlation + baseline risk)
```

---

## 3. Layer Breakdown

### Layer 1: Subnet & Network Interface Detection ([subnet.py](file:///c:/Users/CHAITANYA%20M/ADAPTIVE-CYBER-DEFENSE-SYSTEM/ADAPTIVE-CYBER-DEFENSE-SYSTEM/acds/discovery/subnet.py))
- Detects the primary network adapter holding an active default gateway (Wi-Fi, Ethernet).
- Computes valid network address, broadcast address, and CIDR prefix (e.g. `192.168.1.0/24`).
- Generates the bounded usable IPv4 address list (`192.168.1.1` to `192.168.1.254`).

### Layer 2: Active Layer-2 ARP Probing ([arp.py](file:///c:/Users/CHAITANYA%20M/ADAPTIVE-CYBER-DEFENSE-SYSTEM/ADAPTIVE-CYBER-DEFENSE-SYSTEM/acds/discovery/arp.py))
- Invokes native `SendARP` from Windows `iphlpapi.dll` concurrently across all candidate subnet IPs.
- Layer-2 ARP requests cannot be firewalled by client software (smartphones, IoT, Windows Defender Firewall), ensuring reliable detection of every connected network interface.
- Merges active responses with the system ARP cache table.

### Layer 3 & 4: ICMP Sweeps & Fast TCP Probes ([icmp.py](file:///c:/Users/CHAITANYA%20M/ADAPTIVE-CYBER-DEFENSE-SYSTEM/ADAPTIVE-CYBER-DEFENSE-SYSTEM/acds/discovery/icmp.py), [tcp_probe.py](file:///c:/Users/CHAITANYA%20M/ADAPTIVE-CYBER-DEFENSE-SYSTEM/ADAPTIVE-CYBER-DEFENSE-SYSTEM/acds/discovery/tcp_probe.py))
- Captures ICMP responsiveness and TTL values (TTL $\le 64 \rightarrow$ Linux/Android/macOS, TTL $\le 128 \rightarrow$ Windows, TTL $> 128 \rightarrow$ Network hardware).
- Fast TCP port checks across ports 80, 443, 53, 8080, 445, 139, 8008, 62078.

### Layer 5: Unified Discovery Merge
- Correlates candidate hosts into unified records using IP and MAC.
- Tracks multi-source discovery evidence:
  * `Layer-2 ARP`
  * `ICMP Echo`
  * `TCP Port Probe`
  * `Default Gateway`

### Layer 6: Safe Hostname Resolution
- Resolves hostnames via Reverse DNS (`gethostbyaddr`) and NetBIOS (`nbtstat -A`).
- Failure to resolve hostname never drops the asset.

### Layer 7 & 8: Port Scanning & Banner Grabbing
- Performs multi-threaded socket connection tests across `SCAN_PORTS` for **all discovered hosts**.
- Grabs service banners and parses version strings (e.g. `Apache 2.4.49`, `vsftpd 2.3.4`, `MySQL 5.7.30`).

### Layer 9: Multi-Signal Device & OS Classification ([fingerprint.py](file:///c:/Users/CHAITANYA%20M/ADAPTIVE-CYBER-DEFENSE-SYSTEM/ADAPTIVE-CYBER-DEFENSE-SYSTEM/acds/discovery/fingerprint.py))
- **Gateway Recognition**: Default gateway is classified as `Router / Gateway` (95% confidence).
- **Smart TVs & Media Streamers**: Detected via Roku, LG, Sony, Chromecast, Fire TV OUIs and hostname tokens (`88% confidence`).
- **IoT Devices**: Detected via Espressif (ESP32/ESP8266), Tuya, Raspberry Pi OUIs (`92% confidence`).
- **Mobile Devices & Tablets**: Detected via Apple, Samsung, Xiaomi, OnePlus, Vivo, Oppo, Google Pixel OUIs and client wireless signatures (`90% confidence`).
- **Client Endpoints**: Devices with 0 open ports are preserved as active assets with clear discovery evidence.

### Layer 10: Security & CVE Assessment
- Evaluates confirmed NIST NVD CVEs and baseline service exposure risks.
- Interconnects discovered devices into the logical reachability graph for simulation and defense optimization.

---

## 4. Diagnostics & Reporting Summary

At the end of each network scan, ACDS generates a comprehensive diagnostic summary:

```
DISCOVERY SUMMARY
------------------------------------------------------------
Interface:            Wi-Fi
Local IP:             192.168.1.7
Subnet:               192.168.1.0/24
Default Gateway:      192.168.1.1
Addresses Considered: 254

Total Discovered:     6 unique devices
ARP Discovered:       6
ICMP Discovered:      6
Both ARP + ICMP:      6
ARP Only:             0
ICMP Only:            0
Hostname Resolved:    5
With Open Ports:      4
No Open Ports:        2 (Client mobile / firewalled endpoints)
```
