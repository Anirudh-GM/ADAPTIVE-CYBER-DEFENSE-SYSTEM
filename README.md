# ADAPTIVE CYBER DEFENSE SYSTEM FOR SMEs (ACDS v3.0)

Cybersecurity Attack Simulation, Continuous Risk Intelligence, and Defense Optimization Platform tailored for Small and Medium Enterprises.

---

## 🌟 Overview

The **Adaptive Cyber Defense System (ACDS)** provides an interactive, graph-based security platform designed to empower SMEs with enterprise-grade threat modeling and automated defensive recommendations. 

ACDS combines passive network discovery, NIST NVD CVE vulnerability mapping, dynamic network exposure analysis, simulated lateral-movement attack modeling (MITRE ATT&CK mapped), continuous background asset monitoring, and greedy defense knapsack optimization.

> [!NOTE]
> **Safety & Ethics**: Attack simulations are purely probabilistic graph-theoretic models. **No real exploit payloads, credential attacks, or intrusive traffic are ever generated against target hosts.**

---

## 🚀 Key Features & Dashboard Architecture

ACDS features a streamlined **5-tab command center**:

1. **🏠 Executive Dashboard**:
   - Executive KPIs (Total Assets, Critical Assets, Active CVEs, Overall ACDS Risk, Active Alerts, Average Risk).
   - Plain-English Executive Briefing for non-technical stakeholders.
   - 4-Component Overall Risk Formula Breakdown (`Average Asset Risk × 40% + Blast Radius × 30% + Critical Asset Exposure × 15% + Network Exposure × 15%`).
   - Risk Trend & Severity Distribution charts, plus Top 10 High-Risk Assets table.
2. **⚔️ Attack Simulation & Live Map**:
   - **Unified Side-by-Side Command View**: Real-time interactive PyVis network topology map alongside attack progression.
   - Foothold / Entry Point selector with instant graph path illumination (simulated lateral movement routes, compromised nodes in red, active targets in orange).
   - Bounded 0–100 Blast Radius calculator (Spread, Critical Impact, Attack Depth, Systems Controlled, Critical Assets Reached).
   - Granular step-by-step Attack Timeline cards with MITRE ATT&CK technique tags.
   - Expandable Asset Intelligence Inspector and simulated attack event log.
3. **🛡️ Defense & Remediation**:
   - Greedy knapsack budget optimizer maximizing risk reduction under SME cost constraints.
   - Specific, actionable remediation guidance (exact patches, host isolation, privilege hardening).
   - Adaptive Honeypot Decoy feedback and frequency boosting.
   - Before vs. After Verification matrix re-evaluating risk post-defense.
4. **🧬 Assets & Vulnerabilities**:
   - Live asset inventory and real network scanning monitoring panel.
   - Confirmed CVEs with NIST NVD CVSS scores and confidence ratings.
   - Cross-host CVE deduplication (unique CVE × affected hosts).
   - Vulnerability lifecycle tracking and change detection vs. baseline scans.
5. **🚨 Alerts & Reports**:
   - Dedicated Alert Center with severity filtering, search, and one-click acknowledgement.
   - Multi-format exports: Automated PDF Executive Report (via ReportLab), CSV Asset Inventory, CSV Vulnerability Findings, and Plaintext Summaries.
   - Scan timeline, history audits, and system configuration settings.

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
