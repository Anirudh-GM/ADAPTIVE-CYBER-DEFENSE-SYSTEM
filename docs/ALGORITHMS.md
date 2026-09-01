# ACDS ALGORITHMS & MATHEMATICAL FORMULATIONS

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. 5-Component Asset Risk Model

The static security posture of each discovered or modeled asset is computed using a weighted linear combination of five normalized components:

$$\text{Asset Risk} = (w_1 \cdot V) + (w_2 \cdot E_{\text{svc}}) + (w_3 \cdot E_{\text{sens}}) + (w_4 \cdot C) + (w_5 \cdot E_{\text{net}})$$

Where weights satisfy $\sum_{i=1}^5 w_i = 1.0$:
- $w_1 = 0.40$ (Vulnerability / CVSS component)
- $w_2 = 0.20$ (Service Exposure component)
- $w_3 = 0.15$ (Sensitive Services component)
- $w_4 = 0.15$ (Asset Criticality component)
- $w_5 = 0.10$ (Network Exposure component)

### Component Normalization Formulas:
1. **Vulnerability Component ($V \in [0, 100]$)**:
   $$V = \begin{cases} \max_{c \in \text{CVEs}} (\text{CVSS}_c \times 10) & \text{if confirmed CVEs exist} \\ \max_{e \in \text{Exposures}} (\text{BaseRisk}_e \times 50) & \text{if unversioned exposures exist} \\ 0 & \text{otherwise} \end{cases}$$

2. **Service Exposure Component ($E_{\text{svc}} \in [0, 100]$)**:
   $$E_{\text{svc}} = \min\left(1.0, \frac{|\text{Open Ports}|}{\text{PORT\_EXPOSURE\_CAP}=10}\right) \times 100$$

3. **Sensitive Services Component ($E_{\text{sens}} \in [0, 100]$)**:
   $$E_{\text{sens}} = \min\left(1.0, \frac{|\text{Open Ports} \cap \text{SENSITIVE\_PORTS}|}{\text{SENSITIVE\_PORT\_CAP}=4}\right) \times 100$$
   Where $\text{SENSITIVE\_PORTS} = \{21, 23, 135, 139, 445, 3306, 3389, 5432, 5900, 6379, 27017\}$.

4. **Asset Criticality Component ($C \in [0, 100]$)**:
   $$C = \begin{cases} 100 & \text{if Criticality} = 5 \text{ (Critical / Database)} \\ 67 & \text{if Criticality} = 4 \text{ (High / Production Server)} \\ 33 & \text{if Criticality} = 3 \text{ (Medium / Corporate PC)} \\ 0 & \text{if Criticality} \le 2 \text{ (Low / BYOD Mobile)} \end{cases}$$

5. **Network Exposure Component ($E_{\text{net}} \in [0, 100]$)**:
   $$E_{\text{net}} = \min\left(1.0, \frac{|\text{Open Ports}|}{5}\right) \times \min\left(1.0, \frac{|\text{Other LAN Assets}|}{5}\right) \times 100$$

---

## 2. Dynamic Blast Radius Formula

The dynamic impact of an attack scenario starting from an initial foothold is evaluated as:

$$R_{\text{blast}} = (0.30 \cdot \text{Spread}) + (0.50 \cdot \text{Critical Impact}) + (0.20 \cdot \text{Attack Depth})$$

Where:
- $\text{Spread} = \frac{|\text{Compromised Real Nodes}|}{\max(1, |\text{Total Real Nodes}|)} \times 100$
- $\text{Critical Impact} = \frac{\sum_{n \in \text{Compromised Real}} \text{Criticality}(n)}{\sum_{n \in \text{Total Real}} \text{Criticality}(n)} \times 100$
- $\text{Attack Depth} = \frac{\max(\text{Timesteps})}{|\text{Total Network Nodes}|} \times 100$

**Honeypot Penalty**: If any decoy honeypot is triggered during traversal:
$$R_{\text{blast}} = \min(100.0, R_{\text{blast}} + 15.0)$$

---

## 3. Overall ACDS Risk Synthesis

$$R_{\text{overall}} = (0.60 \cdot \overline{R}_{\text{asset}}) + (0.40 \cdot R_{\text{blast}})$$

Where $\overline{R}_{\text{asset}}$ is the arithmetic mean of all non-honeypot asset risk scores.

---

## 4. Probabilistic Lateral Movement Model

For each directed edge $(u, v)$ from a compromised node $u$ to neighbor $v$:

$$P(\text{compromise}) = \min(0.95, P_{\text{base}}(u, v) \cdot V_{\text{norm}}(v) \cdot D_{\text{global}} \cdot D_{\text{crit}}(v))$$

Where:
- $P_{\text{base}}(u, v)$: Baseline service vulnerability probability ($0.30 - 0.85$).
- $V_{\text{norm}}(v)$: Target normalized vulnerability score ($0.0 - 1.0$).
- $D_{\text{global}}$: Defense dampener ($0.75$ if IDS deployed, $0.55$ if VLAN segmentation active, $0.41$ if both active).
- $D_{\text{crit}}(v) = 0.85$ if $\text{Criticality}(v) \ge 4$ (defense-in-depth on critical systems), else $1.0$.

---

## 5. Heuristic / Greedy Defense Optimization (Knapsack)

Given a set of candidate defenses $D = \{d_1, d_2, \dots, d_m\}$, budget $B$, and candidate cost $c(d_i)$ and expected risk reduction $r(d_i)$:

$$\max_{S \subseteq D} \sum_{d \in S} r(d) \quad \text{subject to} \quad \sum_{d \in S} c(d) \le B$$

### Greedy Heuristic Selection:
1. Compute efficiency ratio: $e(d_i) = \frac{r(d_i)}{c(d_i)}$.
2. Sort candidates in descending order of efficiency: $e(d_{(1)}) \ge e(d_{(2)}) \ge \dots \ge e(d_{(m)})$.
3. Greedily select items into $S$ while $\sum c(d) \le B$.
