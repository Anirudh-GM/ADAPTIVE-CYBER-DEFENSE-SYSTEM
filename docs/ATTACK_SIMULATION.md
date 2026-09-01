# TIME-BASED ATTACK SIMULATION ENGINE

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. Simulation Philosophy & Academic Scope

The ACDS Attack Simulator is a **safe, logical, and probabilistic simulation engine**. It operates strictly in-memory on the NetworkX graph model.

- **No Real Exploits**: It never sends exploitation payloads, credentials, or malicious traffic across the network.
- **Explainable & Deterministic**: Supports reproducible Monte Carlo research and demonstration through explicit pseudo-random seeds.
- **MITRE ATT&CK Alignment**: Every modeled action is tagged with official MITRE ATT&CK technique IDs.

---

## 2. Multi-Step Progression Stages

```
[T1: Initial Foothold] ──> [T2: Lateral Movement] ──> [T3: Privilege Escalation] ──> [T4: Critical Data Exfiltration]
      (T1078)                     (T1021 / T1190)                 (T1068)                          (T1005)
```

1. **Stage 1 (T1) — Initial Foothold (MITRE T1078 / T1190)**:
   The user selects an initial entry point (e.g. `User-PC` compromised via spear-phishing or stolen credential). The system initializes timestep 1.
2. **Stage 2 (T2) — Lateral Movement (MITRE T1021 / T1210)**:
   The engine explores adjacent reachable edges using Breadth-First Search (BFS). For each open port on target systems, a probabilistic compromise roll is evaluated.
3. **Stage 3 (T3) — Privilege Escalation (MITRE T1068)**:
   When an attacker compromises a high-value node ($\text{Criticality} \ge 4$), the engine evaluates privilege escalation (e.g., local root/admin access) at $T + 1$.
4. **Stage 4 (T4) — Decoy Trapping & Defense Boundary Blocking**:
   - Decoy nodes spring traps (MITRE T1003) and log attacker behavior.
   - Isolated hosts reject traversal attempts (MITRE T1599).

---

## 3. Real-Time Generator vs. Batch Mode

The engine provides two execution interfaces:
1. `simulate_attack_step_generator(...)`: Yields `(step_dict, state, lifecycle_event)` at each hop for incremental real-time event streaming and UI animation.
2. `simulate_attack(...)`: Executes BFS traversal to completion and returns `(timeline, compromised_set, honeypot_triggered, stats)` with 100% backward compatibility to the existing Streamlit UI.
