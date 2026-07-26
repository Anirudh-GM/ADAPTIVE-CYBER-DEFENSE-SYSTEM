# VMware Vulnerable Lab Target — Setup Guide

Use this guide to create **one Ubuntu VM** that your ACDS app will discover, profile, and show vulnerabilities for.

## What the app will detect

| Port | Service | Why it matters |
|------|---------|----------------|
| 22 | SSH | Lateral movement vector |
| 80 | HTTP | Web exploit / public-facing app |
| 21 | FTP | Anonymous FTP exposure |
| 23 | Telnet | Cleartext credentials (high risk) |
| 3306 | MySQL | Database exposure on LAN |

The app also grabs **service banners** and looks up **CVEs** when versions are detected.

---

## Part 1 — VMware network (Windows host)

1. Open **VMware Workstation** → **Edit → Virtual Network Editor**
2. Select **VMnet8 (NAT)** — note the subnet (usually `192.168.93.0/24`)
3. Ensure **NAT** is enabled and **DHCP** is on (or use static IP below)
4. Start these Windows services (Run → `services.msc`):
   - **VMware NAT Service** — Running
   - **VMware DHCP Service** — Running

5. Your **Windows host** on VMnet8 is typically `192.168.93.1`  
   The **VM** will use e.g. `192.168.93.128`

> **Important:** ACDS auto-detect **skips** `192.168.93.x` (VMware NAT).  
> In the app you must **uncheck "Auto-detect Base IP"** and set prefix to `192.168.93.`

---

## Part 2 — Create the Ubuntu VM

1. **New VM** → Typical → **Ubuntu 64-bit** (22.04 or 24.04 Server ISO)
2. RAM: **2 GB**, disk: **20 GB**
3. Network adapter: **NAT (VMnet8)** — not Host-Only unless you know routing
4. Install Ubuntu, create user e.g. `labuser`

---

## Part 3 — Run the setup script (inside the VM)

Copy `lab/setup-vulnerable-ubuntu.sh` into the VM, then:

```bash
chmod +x setup-vulnerable-ubuntu.sh
sudo TARGET_IP=192.168.93.128 HOSTNAME=acds-vuln-target bash setup-vulnerable-ubuntu.sh
```

Or clone the repo inside the VM and run from `lab/`.

Reboot if netplan does not apply cleanly:

```bash
sudo reboot
```

After reboot, confirm:

```bash
hostname
ip a
sudo ss -tlnp | grep -E ':21|:22|:23|:80|:3306'
```

---

## Part 4 — Verify from Windows (before scanning in ACDS)

PowerShell on your **Windows host** (where Streamlit runs):

```powershell
ping 192.168.93.128
Test-NetConnection 192.168.93.128 -Port 22
Test-NetConnection 192.168.93.128 -Port 80
Test-NetConnection 192.168.93.128 -Port 3306
```

All should succeed. If ping fails:

- VM is powered on
- VM network = NAT
- VMware NAT/DHCP services running
- Try `ping 192.168.93.1` (host gateway on VMnet8)

---

## Part 5 — Scan in ACDS

1. Run the app: `streamlit run app.py` (or `run_app.bat`)
2. Sidebar → **Real Network Scan**
3. **Uncheck** "Auto-detect Base IP"
4. Base IP prefix: `192.168.93.`
5. Scan range slider: **at least 128** (use **200** to be safe)
6. Click **SCAN NETWORK**

You should see a node like:

**`Server` / `acds-vuln-target (Server)`** or similar with:

- IP `192.168.93.128`
- Services: SSH, HTTP, FTP, MySQL, …
- Vulnerabilities from open ports + CVE lookup
- Access vectors (e.g. SSH brute force, database credential attack)

7. Select that VM as **Entry Point** (or another machine as foothold)
8. Click **RUN ATTACK SIMULATION** to see lateral movement paths

---

## Optional — Second VM (entry point)

Add a second lightweight Ubuntu VM at `192.168.93.10` with only SSH open.  
Compromise **that** as entry point and watch the attack spread to `192.168.93.128`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| VM not in scan results | Increase scan range; ping VM first from Windows |
| Wrong subnet scanned | Use manual prefix `192.168.93.` not auto-detect |
| Ports show closed | `sudo ufw status`; services running (`systemctl status ssh apache2 mysql`) |
| MySQL port closed | `bind-address = 0.0.0.0` in mysqld.cnf, restart mysql |
| Slow scan | Normal — app grabs banners + CVE lookups per host |

---

## Security warning

This VM is **intentionally weak** for education. Use only on **isolated VMware NAT**. Do not port-forward to the internet or attach to production LANs.
