# ADAPTIVE CYBER DEFENSE SYSTEM FOR SMEs (ACDS v3.0)

Cybersecurity Attack Simulation, Continuous Risk Intelligence, and Defense Optimization Platform tailored for Small and Medium Enterprises.

---

## 🌟 Overview

The **Adaptive Cyber Defense System (ACDS)** provides an interactive, graph-based security platform designed to empower SMEs with enterprise-grade threat modeling and automated defensive recommendations. 

ACDS combines passive network discovery, NIST NVD CVE vulnerability mapping, dynamic network exposure analysis, simulated lateral-movement attack modeling (MITRE ATT&CK mapped), continuous background asset monitoring, and greedy defense knapsack optimization.

> [!NOTE]
> **Safety & Ethics**: Attack simulations are purely probabilistic graph-theoretic models. **No real exploit payloads, credential attacks, or intrusive traffic are ever generated against target hosts.**

---

## 🚀 Key Features

- **🌐 Network Discovery & Modeling Engine**:
  - ICMP / ARP / TCP-based active/passive network scanning.
  - MAC Address OUI vendor fingerprinting (Apple, Samsung, Intel, Cisco, etc.).
  - Passive banner grabbing for open services (SSH, HTTP, FTP, MySQL, SMTP, etc.).
  - Automatic asset role and criticality inference with confidence scoring.
- **🔍 NIST NVD CVE Vulnerability Intelligence**:
  - Live query integration with the NIST National Vulnerability Database (NVD) REST API 2.0.
  - Real CVSS v3.x scoring and vulnerability descriptions with automated offline database fallback.
  - Multi-host CVE deduplication across the entire network.
- **🎯 Dynamic Risk Intelligence Engine**:
  - **Overall ACDS Risk Score**: Explainable formula weighting Asset Risk (40%), Blast Radius (30%), Critical Asset Exposure (15%), and Network Exposure (15%).
  - Graph-topology network exposure scoring (reachable assets, degree centrality, sensitive lateral paths).
  - Continuous risk history logging and trend visualizer.
- **⚔️ Attack Path Simulation**:
  - BFS-based lateral movement and simulated privilege escalation.
  - Granular step-by-step MITRE ATT&CK technique mapping (T1021, T1078, T1068, T1190, etc.).
  - Real-time animated attack path visualization with interactive PyVis topology graphs.
  - Honeypot decoy integration with adaptive threat frequency alerting.
- **🛡️ Adaptive Defense Optimizer**:
  - Greedy knapsack optimization maximizing risk reduction under SME budget constraints.
  - Specific, actionable remediation guidance (e.g., specific package patches, isolation, credential hardening).
  - Before vs. After verification re-simulating the attack to validate defense posture.
- **🛰️ Persistent Monitoring & Change Detection**:
  - SQLite persistence layer for lifelong asset lifecycle tracking (`ONLINE` / `OFFLINE`).
  - Automated diff engine detecting new/removed assets, opened/closed ports, service version updates, and risk deltas.
  - Background periodic polling (`st.fragment`) with automated alert generation.
- **📄 Executive Reporting**:
  - One-click PDF Executive Summary report generation (via ReportLab).
  - CSV asset inventory and vulnerability data exports.

---

## 🗺️ MITRE ATT&CK Alignment

| Technique ID | Technique Name | Simulation Context |
|---|---|---|
| **T1021** | Remote Services | Lateral movement via SSH/RDP/SMB services |
| **T1078** | Valid Accounts | Credential reuse across network nodes |
| **T1068** | Exploitation for Privilege Escalation | Local privilege elevation on vulnerable hosts |
| **T1190** | Exploit Public-Facing Application | Initial breach on web servers and exposed endpoints |
| **T1005** | Data from Local System | Targeted exfiltration from high-criticality database hosts |
| **T1003** | OS Credential Dumping | Honeypot decoy interaction detection |

---

## 🛠️ Installation & Setup

### Prerequisites
- **Python 3.8+** (tested on Python 3.10–3.13)
- `pip` package manager

### 1. Clone the Repository
```bash
git clone https://github.com/Anirudh-GM/ADAPTIVE-CYBER-DEFENSE-SYSTEM.git
cd ADAPTIVE-CYBER-DEFENSE-SYSTEM
```

### 2. Create and Activate Virtual Environment

**Windows:**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Running the Application

### Option 1: Using the Batch Launcher (Windows)
Double-click `run_app.bat` or run:
```cmd
.\run_app.bat
```

### Option 2: Using the Streamlit CLI
```bash
streamlit run app.py
```

The application will open in your default browser at:
👉 **`http://localhost:8501`**

---

## 📦 Project Structure

```
ADAPTIVE-CYBER-DEFENSE-SYSTEM/
├── app.py                 # Main Streamlit web application & UI dashboards
├── core/
│   ├── acds_logging.py    # Structured logging infrastructure
│   ├── alert_engine.py    # Real-time event & threat alert generator
│   ├── change_detector.py # Network diff engine (assets, ports, services, CVEs)
│   ├── database.py        # Persistent asset inventory, service & risk history
│   ├── honeypot_engine.py # Honeypot decoy interaction logger & threat signal
│   ├── network_exposure.py# Graph centrality & exposure path calculations
│   └── vuln_dedup.py      # CVE deduplication and cross-host aggregation
├── data/
│   ├── database.py        # Scan history persistence layer
│   └── acds.db            # SQLite database (auto-created on first run)
├── lib/                   # PyVis interactive visualization dependencies
│   ├── bindings/
│   ├── tom-select/
│   └── vis-9.1.2/
├── requirements.txt       # Project Python dependencies
├── run_app.bat            # Windows startup script
├── LICENSE                # MIT License
└── README.md              # Project documentation
```

---

## 📦 Dependencies

- `streamlit>=1.32.0` - Interactive web application framework
- `pandas>=2.0.0` - Data manipulation and tabular analysis
- `networkx>=3.2` - Graph data structures and path algorithms
- `pyvis>=0.3.2` - Interactive network physics visualizer
- `reportlab>=4.0.0` - Automated PDF Executive Report generation
- `requests>=2.31.0` - NIST NVD REST API communication

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is designed exclusively for authorized network defense, educational research, and internal SME risk posture assessment. Always obtain explicit authorization before scanning networks you do not own.
