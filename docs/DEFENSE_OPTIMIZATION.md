# DEFENSE OPTIMIZATION & MODEL MUTATION ENGINE

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. Candidate Defense Actions

ACDS generates specific, actionable defense candidates:

1. **Patching (Type: `patch`)**:
   - Remediation targeting confirmed CVEs on compromised nodes.
   - Cost: $12 + (4 \times \text{Criticality})$.
   - Mutation Effect: Clears `cve_findings`, sets normalized vulnerability component to 0, and recomputes asset risk.
2. **Quarantine / Isolation (Type: `isolate`)**:
   - Host isolation via firewall / ACLs blocking lateral access.
   - Cost: $18 + (6 \times \text{Criticality})$.
   - Mutation Effect: Sets `isolated = True`, sets network exposure component to 0, and blocks inbound/outbound attack edges.
3. **Least Privilege & MFA (Type: `privilege`)**:
   - Enforces privileged access management (PAM) and multi-factor authentication on high-value systems ($\text{Criticality} \ge 4$).
   - Cost: $10 + (3 \times \text{Criticality})$.
   - Mutation Effect: Dampens criticality impact by $40\%$.
4. **Deploy Network IDS / SIEM (Type: `ids`)**:
   - Network-wide detection rules (Snort/Suricata/Wazuh).
   - Cost: 30 units.
   - Mutation Effect: Dampens lateral traversal probability across all edges by $25\%$ ($D_{\text{global}} \times 0.75$).
5. **Network Segmentation / VLANs (Type: `isolate`)**:
   - Splits workstations, servers, and databases into isolated VLANs.
   - Cost: 25 units.
   - Mutation Effect: Dampens cross-subnet lateral traversal probability by $45\%$ ($D_{\text{global}} \times 0.55$).

---

## 2. Model-Mutating Re-Simulation

Applying defenses produces genuine mutations on the in-memory NetworkX model. When the attack simulation is re-run with the same entry point and random seed:
- Compromised nodes drop.
- Attack depth is restricted.
- Risk reduction percentage is calculated honestly from the modified graph.
