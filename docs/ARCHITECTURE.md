# ACDS SYSTEM ARCHITECTURE DOCUMENTATION

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)  
**Version**: 2.1.0  
**Status**: Fully Implemented & Tested

---

## 1. System Overview

The **Adaptive Cyber Defense System (ACDS)** is an intelligent, graph-based cybersecurity decision-support system designed to empower Small and Medium Enterprises (SMEs) to simulate, quantify, and mitigate cyber attack risks within their networks.

The system combines:
1. **Passive Network Discovery & Profiling**: Safe host discovery, TCP port scanning, service banner extraction, and NIST NVD CVE correlation.
2. **5-Component Explainable Asset Risk Engine**: Weighted quantification of node vulnerabilities, service exposures, sensitive ports, criticality ratings, and network connectivity.
3. **Probabilistic Time-Based Attack Simulator**: Multi-step BFS attack propagation modeled after MITRE ATT&CK techniques with honeypot decoy traps and privilege escalation.
4. **Intelligent Honeypot & Adaptive Feedback Engine**: Attacker behavioral telemetry extraction and dynamic risk modification.
5. **Optimization-Based Defense Engine**: Heuristic greedy knapsack resource allocation under budgetary constraints that directly mutates graph simulation models for reproducible Before-vs-After comparison.
6. **Persistence & Headless Experimentation Suite**: Zero-dependency SQLite persistence and Monte Carlo research benchmark runner.

---

## 2. Layered Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                           PRESENTATION LAYER (APPROVED UI)                        |
|   Streamlit HUD Dashboard  |  Cyber Dark Theme (#050a0f)  |  PyVis Physics Graph  |
|   Asset Intelligence Panel |  Before/After Diffs Cards    |  CSV/TXT Exporters    |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        APPLICATION & ORCHESTRATION LAYER                         |
|   app.py (Streamlit State Adapter)  |  EventEngine (acds.core.events)            |
+-----------------------------------------------------------------------------------+
                                         │
    ┌─────────────────┬──────────────────┼──────────────────┬──────────────────┐
    ▼                 ▼                  ▼                  ▼                  ▼
+--------------+ +----------------+ +----------------+ +----------------+ +----------------+
|  DISCOVERY   | | VULNERABILITY  | |   SIMULATION   | |   HONEYPOT     | |    DEFENSE     |
|   PACKAGE    | |   & RISK       | |    PACKAGE     | |  & ADAPTIVE    | |   OPTIMIZER    |
| (acds.disc)  | | (acds.vuln)    | | (acds.sim)     | | (acds.adapt)   | | (acds.def)     |
+--------------+ +----------------+ +----------------+ +----------------+ +----------------+
    │                 │                  │                  │                  │
    └─────────────────┴──────────────────┼──────────────────┴──────────────────┘
                                         ▼
+-----------------------------------------------------------------------------------+
|                         DATA & PERSISTENCE LAYER                                  |
|   NetworkX DiGraph Model  |  SQLite Database Engine (acds.persistence)            |
|   Scan Sessions           |  Simulation Runs       |  Experiment Runs             |
+-----------------------------------------------------------------------------------+
```

---

## 3. Package Structure & Responsibilities

- **`acds.core`**:
  - `constants.py`: Centralized risk weights, port maps, MITRE tags, OUI tables, and offline CVE dictionaries.
  - `models.py`: Strongly-typed dataclasses for Assets, Vulnerabilities, Attack Steps, and Results.
  - `events.py`: Decoupled publisher-subscriber event engine and lifecycle event definitions.
  - `graph.py`: NetworkX graph builders for simulated 7-node lab, live dynamic graphs, and 10–20 node synthetic SME networks.
  - `state.py`: Authoritative state container.

- **`acds.discovery`**:
  - `scanner.py`: Multi-threaded ICMP ping sweep, port scanning, and security assessment orchestrator.
  - `banners.py`: Safe socket banner grabbing and version regex parsing.
  - `arp.py`: System ARP cache reading and MAC address lookup.
  - `fingerprint.py`: Hardware OUI resolution, multi-evidence OS inference, device classification, and criticality assignment.

- **`acds.vulnerability`**:
  - `cve.py`: NIST NVD REST API 2.0 client, CPE range matching, and offline fallback dictionary.
  - `risk.py`: 5-component Asset Risk Model ($40/20/15/15/10$), severity classification, and normalization.
  - `blast_radius.py`: Dynamic blast radius calculation ($0.30 \times \text{spread} + 0.50 \times \text{critical} + 0.20 \times \text{depth}$) and 60/40 Overall ACDS Risk synthesis.

- **`acds.simulation`**:
  - `attack_engine.py`: BFS-based logical attack propagation engine and step-by-step event generator.
  - `attack_state.py`: Simulation state tracker.
  - `attack_paths.py`: Longest routes and critical asset targeting path calculations.
  - `comparison.py`: Before vs After diff engine and percentage risk reduction calculator.

- **`acds.honeypot` & `acds.adaptive`**:
  - `detector.py`: Honeypot decoy node placement and trap detection.
  - `behavior.py`: Attacker interaction telemetry extraction (probed ports, frequency, lateral direction).
  - `feedback.py`: Adaptive feedback signals translating honeypot observations into asset risk boosts.
  - `risk_update.py`: Dynamic risk updates and defense reprioritization.

- **`acds.defense`**:
  - `actions.py`: Candidate defense generator (Patching, Isolation, Least Privilege, IDS/SIEM, VLAN Segmentation) and graph model mutation.
  - `optimizer.py`: Heuristic greedy knapsack optimizer on budget constraints.
  - `policy.py`: Defense policy rules and validation.

- **`acds.persistence`**:
  - `database.py`: Zero-dependency SQLite schema initializer.
  - `repositories.py`: Data access repositories for scans, assets, vulnerabilities, simulations, and defenses.

- **`acds.experiments`**:
  - `runner.py`: Programmatic Monte Carlo sweep and defense budget benchmark runner.
  - `metrics.py`: Descriptive statistical evaluation and CSV/JSON export.

- **`acds.reporting` & `acds.visualization`**:
  - `reports.py`: Plain-English executive summaries and plaintext audit reports.
  - `exports.py`: CSV Asset Inventory and CSV Vulnerability findings exporter.
  - `graph_adapter.py`: Vis.js/PyVis graph renderer with cyberpunk aesthetics.
