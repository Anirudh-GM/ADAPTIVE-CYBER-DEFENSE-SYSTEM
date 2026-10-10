# ACDS v2.0 — System Architecture & Data Flow

## 1. System Overview

The **Adaptive Cyber Defense System for SMEs (ACDS) v2.0** is an enterprise-grade cybersecurity assessment, exposure mapping, and analytical defense-simulation platform. It provides non-destructive security evaluation tailored for small-to-medium enterprises (SMEs) without requiring costly agents or invasive penetration testing tools.

---

## 2. Subsystem Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ACDS Presentation Layer (app.py)                   │
│  ┌───────────┬──────────┬─────────────────┬──────────┬───────────────┐  │
│  │ OVERVIEW  │  ASSETS  │ VULNERABILITIES │ EXPOSURE │ INCIDENTS/DEC │  │
│  ├───────────┼──────────┴─────────────────┼──────────┴───────────────┤  │
│  │ ANALYSIS  │          RESPONSE          │    REPORTS / SETTINGS    │  │
│  └───────────┴────────────────────────────┴──────────────────────────┘  │
└────────────────────────────────────▲────────────────────────────────────┘
                                     │
┌────────────────────────────────────┴────────────────────────────────────┐
│                       Core Analytical Engine (core/)                    │
│ ┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────┐ │
│ │  network_discovery.py   │ │ device_fingerprinting.py│ │live_val.py  │ │
│ │  - Adapter Detection   │ │ - NetBIOS / mDNS / SSDP │ │- L2 Prober  │ │
│ │  - CIDR & Scope Parser │ │ - OUI Vendor / LAA MAC   │ │- Diff Engine│ │
│ └───────────┬─────────────┘ └───────────┬─────────────┘ └──────┬──────┘ │
│             │                           │                      │        │
│ ┌───────────▼─────────────┐ ┌───────────▼─────────────┐ ┌──────▼──────┐ │
│ │  threat_intelligence.py │ │   vuln_dedup.py         │ │change_det.py│ │
│ │  - NVD REST API 2.0     │ │   - CVE Normalization   │ │- State Drift│ │
│ │  - CISA KEV Exploits    │ │   - Multi-Host Dedup    │ │- DHCP Track │ │
│ └───────────┬─────────────┘ └───────────┬─────────────┘ └──────┬──────┘ │
│             │                           │                      │        │
│ ┌───────────▼─────────────┐ ┌───────────▼─────────────┐ ┌──────▼──────┐ │
│ │   adaptive_simulation   │ │  defense_optimizer_v4   │ │alert_corr.py│ │
│ │   - Decision Propagator │ │  - Knapsack Optimizer   │ │- MITRE Map  │ │
│ │   - Analytical Paths    │ │  - Before/After Verify  │ │- Alert Queue│ │
│ └─────────────────────────┘ └─────────────────────────┘ └─────────────┘ │
└────────────────────────────────────▲────────────────────────────────────┘
                                     │
┌────────────────────────────────────┴────────────────────────────────────┐
│                  Data Persistence Layer (data/database.py)              │
│       SQLite3: Assets, CVE Cache, Scan History, Topology Snapshots      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. End-to-End Pipeline Data Flow

The assessment pipeline executes deterministically through 11 distinct phases:

1. **Target Scope Selection:**
   - Operator selects auto-detected local interface (Wi-Fi, Ethernet, VMware VMnet8/VMnet1) or inputs custom target IP / CIDR.
   - Input is validated and parsed into safe IPv4 address lists via `parse_target_ips()`.

2. **Network Discovery:**
   - Multi-threaded ICMP ping / ARP sweep determines reachable hosts without port probing.
   - Initial latency, TTL, and response flags recorded.

3. **Asset Normalization & Identity Tracking:**
   - Invariant `asset_id` generated from MAC address, vendor, and initial attributes.
   - Preserves historical security profile across DHCP IP reassignments.

4. **Service Detection & Protocol Banner Grabbing:**
   - TCP port scanning on standard SME service ports (21, 22, 80, 443, 3306, 3389, 445, 8080, etc.).
   - Protocol-compliant, passive banner grabbing (`HEAD / HTTP/1.1`, SSH identification, MySQL handshake, etc.).
   - Accurate version extraction (`OpenSSH 9.2p1`, `Apache 2.4.58`) with explicit detection status labels.

5. **Multi-Protocol Fingerprinting:**
   - Passive and lightweight UDP queries (NetBIOS UDP 137, mDNS UDP 5353, SSDP UDP 1900).
   - OUI IEEE MAC resolution and Locally Administered Address (LAA) randomized MAC identification.
   - Evidence-based OS and device classification (`Linux Web Server`, `Windows Workstation`, `Database Server`).

6. **Vulnerability Intelligence & CVE Correlation:**
   - Local persistent cache checked first (survives application restarts).
   - NIST NVD REST API 2.0 query with CPE boundary matching.
   - Built-in offline fallback table for zero-connectivity environments.
   - CISA Known Exploited Vulnerabilities (KEV) flag tagging.
   - Missing version evidence documented as `Undisclosed / Unknown` with baseline exposure risk rather than false security claims.

7. **Risk Scoring Model:**
   - **Asset Risk (0–100):**
     $$\text{Asset Risk} = 0.40(\text{Vuln}) + 0.20(\text{Ports}) + 0.15(\text{Sensitive}) + 0.15(\text{Criticality}) + 0.10(\text{Centrality})$$
   - **Overall ACDS Risk (0–100):**
     $$\text{Overall Risk} = 0.40(\text{Avg Asset Risk}) + 0.30(\text{Blast Radius}) + 0.15(\text{Critical Exposure}) + 0.15(\text{Network Exposure})$$

8. **Exposure Topology Graph:**
   - Directed graph ($G = (V, E)$) constructed in NetworkX.
   - Nodes represent discovered physical/virtual assets and decoys.
   - Edges represent legitimate lateral exposure paths based strictly on target open ports and MITRE ATT&CK techniques (T1021, T1190, T1210).
   - Single-host scopes evaluate honestly to 0 lateral edges.

9. **Analytical Attack Simulation:**
   - Non-destructive, probabilistic simulation modeling initial entry point, lateral hopping, and critical asset reachability.
   - Evaluates defense controls (Isolation, Segmentation, IDS detection) without sending live exploit traffic.

10. **Knapsack Defense Optimization:**
    - Greedy / knapsack selection maximizing total risk reduction under operator resource/budget limits.
    - Generates actionable, host-specific remediation instructions.

11. **Before / After Verification & Reporting:**
    - Compares pre-defense baseline metrics against projected or verified post-defense posture.
    - Generates executive summaries, technical audit tables, and CSV/PDF export artifacts.
