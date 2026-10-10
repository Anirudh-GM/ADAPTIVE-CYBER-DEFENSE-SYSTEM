# ACDS v2.0 — Live Academic Demonstration Runbook

## 1. Demonstration Environment Setup

- **Host Operating System:** Windows 11 Home (64-bit)
- **Virtualization:** VMware Workstation 17 Player
- **Target VM:** Kali Linux (`192.168.93.129/24`)
- **VMware Host Adapters:**
  - VMnet8 (NAT): `192.168.93.1`
  - VMnet1 (Host-only): `192.168.193.1`
- **Target Open Services:**
  - TCP Port 22: OpenSSH
  - TCP Port 80: Apache HTTP Server
  - MariaDB: Bound to internal `127.0.0.1:3306` (unreachable from external host interface)

---

## 2. Launching the ACDS Platform

Open PowerShell in the project directory and start the Streamlit SOC Console:
```powershell
# Option A: Using the provided launcher script
.\run_app.bat

# Option B: Direct PowerShell launch
.\venv\Scripts\Activate.ps1
streamlit run app.py
```
The application will open in your default browser at `http://localhost:8501`.

---

## 3. Step-by-Step Demonstration Procedure

### Step 1: Interface & Scope Selection
1. In the sidebar under **Environment**, ensure **Production Network** (Real Network Scan) is selected.
2. Under **Assessment Scope & Interface**, observe the automatically enumerated adapters:
   - `WiFi (10.192.177.60)`
   - `VMware Network Adapter VMnet8 (192.168.93.1)`
   - `VMware Network Adapter VMnet1 (192.168.193.1)`
   - `🎯 Custom Target Scope / IP`
3. Select either `VMware Network Adapter VMnet8 (192.168.93.1)` or `Custom Target Scope / IP` and specify `192.168.93.129`.
4. Click **📡 START ASSESSMENT**.

### Step 2: Asset Discovery & Investigation (Overview & Assets Pages)
1. Navigate to **OVERVIEW**:
   - Observe the updated KPI metrics: Discovered Assets, Open CVEs, Active Alerts, and Overall Risk Score.
2. Navigate to **ASSETS**:
   - Observe the Kali host listed in the inventory table: `192.168.93.129 (Linux Web Server)`.
   - In the **Asset Deep-Dive Investigation** drawer:
     - Open **🔌 Services & Ports** sub-tab: Note that Port 22 (SSH) and Port 80 (HTTP) are displayed with exact detection status (`Version Detected`), version (`OpenSSH 9.2p1`, `Apache 2.4.58`), and service banners.
     - Open **🛡️ Vulnerabilities (CVEs)** sub-tab: View correlated CVE findings or the honest intelligence status explaining why unversioned services cannot be matched against NVD without version disclosure.
     - Open **📊 Risk Score Breakdown** sub-tab: Observe the 5 weighted components (40% Vuln, 20% Exposure, 15% Sensitive, 15% Criticality, 10% Centrality).
     - Click **⚡ Run Live Validation**: Observe active socket latency and port reachability confirmation.

### Step 3: Vulnerability Intelligence & CISA KEV (Vulnerabilities Page)
1. Navigate to **VULNERABILITIES**:
   - Filter by severity (Critical / High / Medium / Low).
   - Filter by **CISA KEV (Actively Exploited) Only** to highlight known weaponized vulnerabilities.
   - Inspect the remediation guidance cards for actionable upgrade instructions.

### Step 4: Attack Surface Topology (Exposure Page)
1. Navigate to **EXPOSURE**:
   - Observe the interactive PyVis graph representing active topology nodes.
   - Note the single-asset notice: since only 1 asset was scanned, 0 lateral edges are present (confirming ACDS does not fabricate false lateral relationships).
   - Toggle layout modes between Force-Directed physics and Hierarchical tiered architecture.

### Step 5: Analytical Attack Simulation (Analysis Page)
1. Navigate to **ANALYSIS** -> **⚔️ Modeled Attack Path Simulation**:
   - Select the Kali host as the simulated entry point.
   - Click **▶ RUN ATTACK SIMULATION**.
   - Review the simulation outcome cards: Compromised Host Count, Blast Radius Score, Attack Depth, and Decoy Trigger status.
   - View the step-by-step analytical propagation timeline with MITRE ATT&CK technique IDs (T1021, T1190).

### Step 6: Budget-Constrained Defense Optimization & Verification (Response Page)
1. Navigate to **RESPONSE** -> **💰 Budget Defense Optimizer**:
   - Adjust the security budget slider (e.g. 50 resource points).
   - Observe the greedy knapsack optimizer selecting the highest risk-reduction defense actions.
   - Click **⚡ APPLY OPTIMIZED DEFENSES TO MODEL**.
2. Switch to **📏 Before / After Verification**:
   - Compare the pre-defense baseline against the projected post-defense metrics.
   - Verify the exact risk score reduction and closed attack paths.

### Step 7: Reports & Executive Handover (Reports Page)
1. Navigate to **REPORTS**:
   - Review the Executive Security Summary and Technical Assessment tables.
   - Export assessment data via CSV or PDF for compliance records.

---

## 4. Recovery & Troubleshooting Procedures

- **Kali Target Not Responding:** Ensure Kali VM is running in VMware Player and VMware Network Adapter VMnet8 is enabled in Windows Network Connections. Test connectivity via `Test-NetConnection -ComputerName 192.168.93.129 -Port 80` in PowerShell.
- **NVD API Rate Limiting:** ACDS automatically falls back to its local SQLite CVE cache and built-in offline CVE reference table without interrupting the scan.
- **Resetting In-Memory State:** Switch environment in the sidebar to **Simulated Lab** and back to **Production Network** to clear session cache.
