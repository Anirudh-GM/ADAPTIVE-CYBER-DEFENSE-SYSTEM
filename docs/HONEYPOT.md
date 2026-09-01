# INTELLIGENT HONEYPOT & DECEPTION ENGINE

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. Role in the ACDS Architecture

Honeypots in ACDS serve as **active deception sensors**. Rather than merely detecting a breach after critical systems have been accessed, honeypots are positioned along potential lateral movement paths (e.g., exposed on DMZ or internal broadcast domains with intentionally enticing services like FTP, Telnet, SMB, or SSH).

---

## 2. Decoy Attributes & Detection Logic

When an attacker attempts lateral traversal toward a honeypot node:
1. **Decoy Signature**:
   - `node_type = "honeypot"`
   - `criticality = 1` (Carries zero enterprise business value)
   - `vulnerability = 0.90` (High vulnerability lure)
2. **Detection & Alert**:
   - Traps lateral scans under MITRE ATT&CK technique **T1003 (OS Credential Dumping / Decoy Probe)**.
   - Emits a high-severity `HONEYPOT_TRIGGERED` lifecycle event.
   - Updates `honeypot_triggered = True` in simulation state.
   - Adds a quantitative $+15$ penalty to the network blast radius score.

---

## 3. Telemetry Recorded

For every interaction with a decoy system, the engine records:
- Attacker Origin Host
- Probed Destination Honeypot Node
- Targeted Port & Service
- Lateral Traversal Access Vector
- Interaction Timestep
- Probe Velocity (Interactions per Timestep)
