# ACDS v2.0 — Known Limitations & Technical Scope Boundaries

## 1. Scope & Architectural Boundaries

ACDS v2.0 is specifically designed as a non-destructive assessment, risk quantification, and analytical defense-simulation platform for Small and Medium Enterprises (SMEs). The following operational boundaries are intentionally enforced to ensure safety, ethical compliance, and reliability:

### 1. Non-Destructive / Non-Exploitative Simulation
- **Design Principle:** ACDS does not execute active exploits, send malicious shellcode, perform brute-force credential attacks, or compromise remote target operating systems.
- **Limitation:** Attack paths and lateral movements are evaluated analytically using graph reachability, open port indicators, and probabilistic models based on known CVE severity and service exposure.

### 2. Service Version Disclosure & Withheld Banners
- **Design Principle:** ACDS adheres strictly to evidentiary standards and never fabricates service versions to trigger CVE matches.
- **Limitation:** When a server daemon (e.g. hardened web server with `ServerTokens Prod` or custom firewalls) withholds version banners, ACDS assigns a baseline exposure risk score rather than a specific CVE. This is an intentional security design choice.

### 3. Loopback & Non-Exposed Services
- **Design Principle:** Network assessments discover services listening on external IPv4 interfaces.
- **Limitation:** Services bound strictly to `127.0.0.1` (such as MariaDB on port 3306 on our Kali lab VM) cannot be detected from an external network scanner unless port forwarding or local agent access is provided.

### 4. Single-Host Lateral Movement Boundaries
- **Design Principle:** Lateral movement requires at least two network endpoints to model relationship edges.
- **Limitation:** When scanning a single target IP (e.g. `192.168.93.129`), the topology graph will display 1 node and 0 lateral edges. Multi-hop propagation paths require assessing a subnet containing two or more responsive endpoints.

### 5. NVD API Rate Limits & Offline Fallback
- **Design Principle:** ACDS integrates live NIST NVD REST API 2.0 with local caching and offline fallback.
- **Limitation:** High-frequency scans without a registered NIST NVD API key may trigger rate limits (5 requests per 30-second window), prompting ACDS to utilize its built-in offline historical intelligence catalog.

---

## 2. Recommended Production Hardening Roadmap

1. Optional NIST NVD API Key configuration in `Settings` for higher request throughput.
2. Integration with enterprise Active Directory / LDAP for credentialed asset discovery.
3. Automated firewall rule push API integrations for supported enterprise perimeter hardware.
