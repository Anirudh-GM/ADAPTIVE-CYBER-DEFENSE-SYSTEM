# ACDS v4.0 — What's New

## 13 New Phases Added (All Backward-Compatible)

### Phase 1 + 11 — Explainable Attack Path Intelligence + MITRE Enhancement
- Every graph edge now contains: source/target, port, service, protocol, reachability,
  live port state, vulnerability condition, MITRE technique (only when conditions satisfied),
  defense state, probability, human-readable reason
- MITRE techniques are NEVER assigned without supporting port/service evidence (Phase 11)
- New module: `core/attack_graph_intelligence.py`

### Phase 2 — Graph-Aware Risk Prioritization
- Replaces simple CVSS ranking with 7-component graph-aware score:
  CVSS · Exposure · Reachability · Attack Paths · Downstream Critical · Blast Radius · Confidence
- Every asset explains WHY its priority is High or Critical
- New module: `core/graph_risk_prioritizer.py`

### Phase 3 — Adaptive Attack Simulation
- Graph is now dynamic: new asset/port/CVE → graph auto-updates
- Detects topology changes between scans
- Stores historical topology timeline in SQLite
- New module: `core/adaptive_simulation.py`
- New DB table: `topology_snapshots`

### Phase 4 — Advanced Defense Optimization (8 Action Types)
- 8 defense types: Patch · Close Port · Disable Service · Firewall Rule ·
  VLAN Segmentation · Host Isolation · Monitoring · Honeypot Placement
- Every action: cost, risk reduction, blast radius reduction, paths removed,
  critical assets protected, WHY it was selected
- New module: `core/defense_optimizer_v4.py`

### Phase 5 — Closed-Loop Adaptive Defense
- Full cycle: Observe→Assess→Model→Simulate→Rank→Select→Apply→Re-Validate→Re-Simulate→Measure→Monitor
- BEFORE vs AFTER: Overall Risk · Blast Radius · Attack Paths · Critical Assets · Cost
- Always labelled SIMULATION
- New module: `core/adaptive_cycle.py`

### Phase 6 — SME Multi-Node Lab
- 5-node lab: Workstation · File Server · Web Server · Database · Admin PC
- IPs discovered dynamically (no hardcoding)
- VirtualBox Host-only / Internal networking support
- Model validation report against expected attack paths
- New module: `core/sme_lab.py`

### Phase 7 + 8 — Continuous Monitoring + Intelligent Alert Correlation
- Detects: New Device · Removed · IP Change · New Service · New CVE · New Attack Path
- Correlates related events → ONE compound alert with root cause, CVE, path, recommendation
- Deduplication prevents duplicate alerts within window
- New module: `core/alert_correlator.py`

### Phase 9 — Historical Security Intelligence
- Risk trend · Asset trend · Attack-path trend · Defense effectiveness
- SQLite-backed trend data with chart-ready series
- New module: `core/historical_intelligence.py`
- New DB helpers: `get_risk_history_summary`, `get_asset_count_trend`, `get_topology_history`

### Phase 10 — Threat Intelligence
- CISA KEV (Known Exploited Vulnerabilities) offline catalog — 10 real entries
- Priority boost ONLY when asset is exposed AND reachable (conditions enforced)
- NVD integration extended, vendor advisory hints
- New module: `core/threat_intelligence.py`

### Phase 11 — MITRE Enhancement
- See Phase 1 above. Every technique requires: matching port + service conditions.
- Never assigns technique without supporting evidence.

### Phase 12 — Professional Reporting
- 15-section report: Executive Summary · Network Overview · Asset Inventory ·
  Vulnerability · Risk · Critical Assets · Attack Graph · Blast Radius · MITRE ·
  Defense Optimization · Cost vs Risk · Before/After · Historical Trends · Alerts · Final Posture
- PDF (reportlab) + CSV export
- New module: `core/report_generator_v4.py`

### Phase 13 — Final Product Polish
- Three concepts clearly distinguished everywhere:
  - **REAL OBSERVATION** — passive scan data
  - **REAL-TIME VALIDATION** — live ICMP/TCP/banner checks
  - **SIMULATION** — graph-modeled attack paths (never presented as real compromise)
- Simulation label present on every edge, action, comparison, and cycle stage

## New Tests
- `tests/test_v4_phases.py` — 58 new tests covering all 13 phases
- Total test suite: **72 tests, all passing**

## New UI Tab
- **🚀 v4.0 Intelligence Hub** — 10 sub-tabs, one per phase group
- All existing tabs unchanged

## Database
- New table: `topology_snapshots` (Phase 3)
- Fresh-DB migration: `monitor_db.init_db()` creates all tables including new one
- Zero breaking changes to existing schema

## Safety
- Passive scanning only — no exploitation, no credential attacks
- All attack propagation remains SIMULATION in graph model
- CISA KEV boost only when exposure conditions are actually satisfied
- MITRE techniques only assigned when port/service conditions are confirmed
