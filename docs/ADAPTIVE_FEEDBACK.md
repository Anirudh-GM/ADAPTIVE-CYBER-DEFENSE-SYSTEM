# ADAPTIVE FEEDBACK & DYNAMIC RISK UPDATE ENGINE

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. The Closed-Loop Feedback Concept

A cornerstone of the ACDS research model is the **Adaptive Feedback Loop**:

```
[Honeypot Trap Observation]
             ↓
[Attacker Behavioral Telemetry] (Probed ports, targeted protocols, velocity)
             ↓
[Adaptive Feedback Signals] (Identifies exposed production assets with matching services)
             ↓
[Dynamic Asset Risk Update] (Raises risk on assets in attacker's active crosshairs)
             ↓
[Defense Reprioritization] (Multiplies efficiency of defenses on targeted assets)
```

---

## 2. Adaptive Risk Formula

When an attacker actively probes specific protocols at the honeypot (e.g. FTP port 21 or SMB port 445), other production nodes running those same protocols are under imminent threat.

The dynamic risk delta is evaluated as:

$$\Delta R_{\text{adaptive}}(n) = \min\left(15.0, 5.0 \cdot |S_{\text{matched}}| + 3.0 \cdot |P_{\text{matched}}|\right)$$

And updated node risk:

$$R_{\text{updated}}(n) = \min(100.0, R_{\text{base}}(n) + \Delta R_{\text{adaptive}}(n))$$

---

## 3. Defense Priority Multiplier

Defending assets with services matching the attacker's active TTPs yields higher defense priority. Candidate defenses on these nodes receive a **$1.35\times$ efficiency multiplier**:

$$e_{\text{adaptive}}(d) = e_{\text{base}}(d) \times 1.35$$

This ensures the greedy knapsack algorithm prioritizes patching and isolating systems directly in the path of the observed adversary.
