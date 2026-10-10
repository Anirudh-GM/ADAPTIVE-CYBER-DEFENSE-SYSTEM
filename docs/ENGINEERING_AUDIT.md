# ACDS v2.0 — Comprehensive Engineering Audit & Defect Remediation Report

## 1. Executive Summary

This engineering audit document provides a verified, evidence-based review of the **Adaptive Cyber Defense System for SMEs (ACDS) v2.0** codebase. The audit inspected the complete assessment pipeline, frontend state management, threat intelligence lookups, risk calculation formulas, exposure graph topology, attack simulation, knapsack defense optimization, and before/after verification workflows.

All identified runtime exceptions, HTML injection leaks, data-flow gaps, adapter selection constraints, and banner-parsing defects have been corrected and verified across 84 automated unit tests.

---

## 2. Audit Findings & Remediations Table

| Finding | Evidence | Severity | Root Cause | Proposed Fix | Verification |
|---|---|---|---|---|---|
| **Blank Service Versions & Banners in UI** | Kali target (`192.168.93.129`) had open ports 22 and 80, but Asset table displayed `—` for Detected Version and Service Banner. | **High (Defect)** | In `app.py`, `render_assets_page()` constructed `asset_list` from `G.nodes` without copying `version_map` and `banner_map`. Furthermore, the Services sub-tab looked for dictionary attributes on `selected_asset['services']` which was stored as a list of names. | Enriched asset dictionary to include `version_map`, `banner_map`, `risk_components`, and `exposure_findings`. Rewrote Services sub-tab to correlate ports with `version_map` and `banner_map`, displaying explicit detection status (`Version Detected`, `Banner Obtained`, `Port Open (Banner Withheld)`). | Verified in `test_audit_pipeline.py` (`test_banner_parsing_openssh`, `test_banner_parsing_apache`, `test_single_asset_graph`) and manual live inspection. |
| **VMware NAT Subnet Omission in Auto-Discovery** | Subnet auto-discovery only bound to the default outbound socket (Wi-Fi `10.192.177.60/24`), ignoring VMware VMnet8 (`192.168.93.1/24`) and VMnet1 (`192.168.193.1/24`). | **High (Design Inconsistency)** | `detect_network_environment()` parsed `ipconfig` lines but only returned the single adapter matching the default outbound routing route. | Enhanced `detect_network_environment()` to populate `all_adapters` with all active network adapters (names, IPs, subnet CIDRs, netmasks, gateways). Added an interactive interface/scope selector in the sidebar. | Verified via `test_multi_adapter_discovery` and runtime execution on Windows 11 host. |
| **HTTP & SSH Banner Grabbing Limitations** | HTTP servers requiring standard headers (User-Agent, HTTP/1.1) did not return `Server:` headers on bare `HEAD / HTTP/1.0`. | **Medium (Defect)** | `grab_banner()` sent minimal `HEAD / HTTP/1.0` without user-agent, causing modern servers to return 400 Bad Request or omit headers. | Enhanced `grab_banner()` to send compliant `HTTP/1.1` requests with `User-Agent: ACDS-Scanner/2.0` and fallback to lightweight `GET /`, plus support for MySQL handshake packet version extraction. | Verified via `test_banner_parsing_apache` and live Kali Apache testing. |
| **Streamlit Unpack & List Attribute Errors** | Runtimes raised `ValueError: too many values to unpack (expected 5)` on Analysis page and `AttributeError: 'list' object has no attribute 'get'` on Response page. | **High (Defect)** | `simulate_decision_based_propagation` returns 7 values (`timeline, decision_log, compromised, uncompromised, successful_paths, blocked_failed_paths, attack_stats`) but caller unpacked 5. `selected_defenses` were checked via `.get()` on a list object. | Fixed unpack signature and standardized dictionary access on defense action items. | Verified in `render_analysis_page()` and `render_response_page()` automated runs. |
| **Raw HTML Indentation / Badge Leaks** | Frontend rendered literal raw text `</div><div><span class="badge-category badge-real">● REAL OBSERVATION</span></div>`. | **Medium (UX Defect)** | Multiline triple-quoted strings inside `_soc_header()` and cards had leading Python indentation that Markdown parsers treated as `<pre>` code blocks. | Sanitized all HTML templates by eliminating leading whitespace indentation in markdown template strings. | Verified across all 9 SOC pages without HTML leaks. |
| **Single-Asset Lateral Path Representation** | Single-host assessment showed confusing empty exposure state without explanation. | **Low (UX / Clarity)** | Single host has 0 inbound and 0 outbound lateral paths to other nodes, but UI lacked context. | Added explicit explanation in Exposure page and Asset detail drawer explaining that a single host has zero lateral paths to other assets by definition. | Verified in `test_single_asset_graph`. |
| **Criticality vs Security Risk Semantic Disconnect** | Asset with HIGH criticality (Tier 4) displayed LOW risk score, confusing operators. | **Medium (Clarity)** | Criticality reflects business value/impact (e.g. database server), while Risk reflects active vulnerability and exposure likelihood. Hardened servers have high criticality but low risk. | Added detailed 5-part formula breakdown card explaining the distinction between Business Criticality and Active Threat Risk. | Verified in `render_assets_page()` risk breakdown tab and `test_risk_score_calculation`. |
| **Before / After Defense State Baseline Retention** | Applying modeled defenses could overwrite the pre-defense baseline metrics if not captured prior to execution. | **Medium (Design Inconsistency)** | Session state lacked persistent pre-defense snapshot keys before knapsack defense optimization. | Captured `overall_acds_risk_before`, `risk_before_defense`, and `blast_before_defense` prior to defense application to guarantee honest before/after comparison. | Verified in `test_defense_knapsack_and_before_after`. |

---

## 3. Classification of Subsystems

1. **Confirmed Defects (Resolved):**
   - Service table version and banner extraction rendering.
   - Streamlit unpack and defense optimizer list access.
   - HTTP/1.1 User-Agent header omission in banner grabbing.
   - HTML template indentation causing code block leaks.

2. **Confirmed Design Inconsistencies (Resolved):**
   - Single default adapter assumption resolved with multi-adapter enumeration.
   - Missing version evidence now explicitly labeled as `Undisclosed / Unknown` rather than implying complete security.
   - Baseline exposure findings surfaced when no CVE matches.

3. **Working as Intended & Verified:**
   - 5-part weighted Asset Risk model (40% Vuln, 20% Exposure, 15% Sensitive, 15% Criticality, 10% Centrality).
   - 4-part Overall ACDS Risk aggregation (40% Asset, 30% Blast, 15% Critical, 15% Network).
   - Analytical, non-destructive attack propagation simulator.
   - Greedy budget-constrained knapsack defense optimizer.
   - CISA Known Exploited Vulnerabilities (KEV) catalog correlation.
   - SQLite historical posture and asset audit trail.
