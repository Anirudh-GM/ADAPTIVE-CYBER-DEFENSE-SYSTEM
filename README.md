# ADAPTIVE CYBER DEFENSE SYSTEM FOR SMEs

Cybersecurity Attack Simulation & Defense Platform for Small and Medium Enterprises

## Overview

This system provides an interactive platform for simulating cyber attacks on network infrastructure and optimizing defense strategies. It uses graph-based modeling to represent network topology, BFS-based attack path simulation, and greedy optimization algorithms for defense resource allocation.

## Features

- **Network Modeling Engine**: Build and visualize network topologies with node attributes (IP, role, criticality, vulnerability)
- **Real Network Scan**: Discover live devices on your network via ICMP ping
- **Attack Simulation**: BFS-based attack path simulation with MITRE ATT&CK technique mapping
- **Risk Assessment**: Calculate blast radius and risk scores based on spread, critical impact, and attack depth
- **Defense Optimization**: Greedy knapsack algorithm for optimal defense action selection within budget constraints
- **Interactive Visualization**: PyVis-powered network graphs with cyberpunk styling
- **Honeypot Integration**: Decoy systems for attack detection and alerting

## MITRE ATT&CK Alignment

- **T1021** - Remote Services (lateral movement via SSH)
- **T1078** - Valid Accounts (credential reuse)
- **T1068** - Exploitation for Privilege Escalation
- **T1005** - Data from Local System (database exfiltration)
- **T1190** - Exploit Public-Facing Application
- **T1003** - OS Credential Dumping (honeypot trap)

## Virtual Lab Mapping

This system maps to a real UTM virtual lab environment:

```
VM1 (User-PC)   → 192.168.1.10  → Entry point, simulates attacker's foothold
VM2 (Server)    → 192.168.1.20  → Apache web server, lateral movement target
VM3 (Database)  → 192.168.1.30  → MySQL database, high-value target
```

### UTM Setup Steps (MacBook M4 / Apple Silicon)

1. Download UTM from https://mac.getutm.app/
2. Download Ubuntu 22.04 ARM64 ISO from https://ubuntu.com/download/server/arm
3. Create VM: New → Virtualize → Linux → Browse ISO
4. Set RAM: 2048MB, CPU: 2 cores, Storage: 20GB
5. Repeat for 3 VMs, assign static IPs via /etc/netplan
6. Enable UTM Shared Network for inter-VM connectivity
7. Verify: ping 192.168.1.20 from VM1

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd ADAPTIVE-CYBER-DEFENSE-SYSTEM
```

2. Create a virtual environment:
```bash
python -m venv .venv
```

3. Activate the virtual environment:

**Windows:**
```bash
.venv\Scripts\activate
```

**Linux/Mac:**
```bash
source .venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Run the Application

**Windows:**
```bash
run_app.bat
```

**Linux/Mac:**
```bash
streamlit run app.py
```

The application will open in your default web browser at `http://localhost:8501`

### Application Modes

1. **Simulation Mode**: Use predefined network topology for attack simulation
2. **Real Network Mode**: Scan your actual network and build dynamic graph from discovered devices

### Defense Actions

The system recommends defense actions based on:
- **Patch**: Apply security patches to vulnerable nodes
- **Isolate**: Network quarantine of compromised nodes
- **Reduce Privileges**: Enforce least privilege on critical systems
- **Deploy IDS**: Network-wide intrusion detection

## Requirements

```
streamlit>=1.57.0
networkx>=2.8.0
pyvis>=0.3.2
pandas>=2.0.0
numpy>=2.0.0
```

## Project Structure

```
ADAPTIVE-CYBER-DEFENSE-SYSTEM/
├── app.py                 # Main Streamlit application
├── requirements.txt       # Python dependencies
├── run_app.bat           # Windows launch script
├── lib/                  # PyVis local resources
│   ├── bindings/
│   ├── tom-select/
│   └── vis-9.1.2/
├── .venv/                # Virtual environment (gitignored)
└── temp/                 # Temporary files (gitignored)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for educational and defensive purposes only. Always obtain proper authorization before scanning or testing any network infrastructure.
