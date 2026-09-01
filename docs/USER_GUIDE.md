# ACDS USER & OPERATIONAL GUIDE

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. Quick Start

### Launching the Dashboard:
**Windows**:
```bash
run_app.bat
```
**Linux / macOS**:
```bash
streamlit run app.py
```

The application will launch in your default web browser at `http://localhost:8501`.

---

## 2. Operational Modes

### Mode 1: Simulated Lab Mode (Default Demo Mode)
- Pre-loads an enterprise 7-node network (Firewall, User PC, Admin PC, Web Server, File Server, MySQL Database, and Honeypot Decoy).
- Allows instant attack simulation, risk inspection, defense optimization, and Before/After diffs without scanning live hardware.

### Mode 2: Real Network Scan Mode
1. In the sidebar, select **Real Network Scan**.
2. Select your network preset:
   - **VMware NAT (192.168.93.x)** for virtualized lab testing.
   - **Home LAN (192.168.1.x)** for local subnet discovery.
   - **Custom / Auto** to auto-detect your local IP.
3. Set the scan range slider (e.g. up to 100 or 254).
4. Click **📡 SCAN NETWORK**.
5. The system performs multi-threaded host ping sweeps, TCP port scans, banner grabs, OS/device inference, and live NIST NVD CVE lookups.

---

## 3. Running an Attack Simulation

1. Under **⚙ SIMULATION CONTROLS** in the sidebar, select an initial **Entry Point** (the initial compromised foothold, e.g. `User-PC`).
2. Adjust the animation speed slider if desired.
3. Click **▶ RUN ATTACK SIMULATION**.
4. Observe the step-by-step attack propagation on the PyVis topology graph.
5. Review the **Simulated Attack Timeline**, **Network Blast Radius**, and **Executive Summary**.

---

## 4. Applying Defenses & Comparing Results

1. In the **🛡 ACDS DEFENSE OPTIMIZATION** section, adjust the **Defense Budget (units)** slider.
2. The greedy knapsack algorithm will automatically select the highest-efficiency candidate defenses.
3. Click **🛡 APPLY SELECTED DEFENSES**.
4. The system will mutate the underlying graph model, re-run the attack simulation under identical conditions, and display the **BEFORE vs. AFTER** comparison cards showing the exact risk reduction percentage.
5. Download your **Asset Inventory (CSV)**, **Vulnerability Report (CSV)**, or **Executive Report (TXT)** from the **📤 REPORTING / EXPORT** panel.
