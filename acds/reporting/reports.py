"""
ACDS Executive Reporting Engine
Formats plain-English executive summaries, MITRE-mapped attack event logs, and plaintext audit reports.
"""

from typing import Dict, List, Optional, Set, Any
import networkx as nx
from acds.vulnerability.risk import severity_from_score


def generate_attack_log(
    timeline: List[Dict[str, Any]],
    honeypot_triggered: bool,
) -> List[Dict[str, Any]]:
    """Convert raw attack timeline steps into structured attack log entries for display."""
    log = []
    mitre_log = {
        "T1190": "exploit_public_app", "T1078": "valid_account_brute",
        "T1021": "lateral_move", "T1005": "data_staged_exfil",
        "T1003": "credential_dump_lsass", "T1068": "priv_esc",
        "T1599": "boundary_blocked",
    }
    for entry in timeline[:12]:
        action = mitre_log.get(entry.get("mitre_code", ""), "scan_probe")
        status = "POTENTIAL PATH" if entry["success"] else "BLOCKED"
        severity = "critical" if entry["success"] else "ok"
        log.append({
            "src": "Simulated Attacker",
            "target": entry["node"],
            "action": action,
            "technique": f"{entry.get('mitre_code','')}: {entry.get('mitre_desc','')}",
            "reason": entry.get("access_vector", "network"),
            "status": status,
            "severity": severity,
        })
    if honeypot_triggered:
        log.append({
            "src": "Simulated Attacker",
            "target": "Honeypot",
            "action": "HONEYPOT_TRIGGER",
            "technique": "T1003 — Credential Dumping [TRAP]",
            "reason": "Decoy service probed",
            "status": "⚠ TRAP SPRUNG (simulated)",
            "severity": "critical",
        })
    return log


def build_executive_summary(
    G: nx.DiGraph,
    compromised: Set[str],
    risk_score: float,
    blast_details: Dict[str, Any],
    entry_node: Optional[str],
) -> str:
    """Build plain-English summary for non-technical SME leadership."""
    real_compromised = [n for n in compromised if G.nodes[n].get("node_type") != "honeypot"]
    crown_jewels = [n for n in real_compromised if G.nodes[n].get("criticality", 2) >= 4]

    all_cves = []
    for n in G.nodes:
        all_cves.extend(G.nodes[n].get('cve_findings', []))
    all_cves.sort(key=lambda c: c.get('cvss', 0.0), reverse=True)
    top_cve = all_cves[0] if all_cves else None

    risk_word = severity_from_score(risk_score)

    lines = []
    lines.append(
        "<b>SIMULATION ONLY — no real attack traffic was generated and no exploitation was performed.</b>"
    )
    lines.append(
        f"Starting from <b>{(entry_node or 'the chosen entry point').split(chr(10))[-1]}</b>, "
        f"this simulation estimates an attacker could potentially reach "
        f"<b>{len(real_compromised)} of {blast_details.get('total_real_nodes', len(G.nodes))}</b> "
        f"systems on your network, including <b>{len(crown_jewels)}</b> high-value system(s) "
        f"such as servers or databases."
    )
    if top_cve:
        lines.append(
            f"The single most dangerous CONFIRMED issue found was <b>{top_cve['cve_id']}</b> "
            f"(CVSS {top_cve['cvss']}) on the <b>{top_cve['service']}</b> service "
            f"(port {top_cve['port']}). Fixing this first gives the largest risk reduction "
            f"for the least effort."
        )
    else:
        lines.append(
            "No version-specific CONFIRMED CVE was found on this network. Remaining risk comes "
            "from exposed services / weak configuration rather than a matched vulnerability."
        )
    lines.append(
        f"Overall business risk is rated <b>{risk_word}</b> ({risk_score}/100). "
        f"{'This needs attention this week.' if risk_word=='CRITICAL' else 'This should be scheduled into your next IT maintenance window.' if risk_word=='HIGH' else 'Address opportunistically as part of routine maintenance.' if risk_word=='MEDIUM' else 'No urgent action required, but keep monitoring.'}"
    )
    return "<br><br>".join(lines)


def get_asset_metrics(G: nx.DiGraph) -> Dict[str, Any]:
    """Calculate asset summary metrics without mutating the graph."""
    assets = list(G.nodes(data=True))
    risks = [float(data.get("risk_score", data.get("vulnerability", 0.0) * 100.0)) for _, data in assets]
    services = sum(len(data.get("services", [])) for _, data in assets)
    servers = sum(data.get("node_type") in {"server", "database"} for _, data in assets)
    other = sum(data.get("node_type") not in {"server", "database", "honeypot", "perimeter"} for _, data in assets)
    critical = sum(any(c.get("cvss", 0.0) >= 9.0 for c in data.get("cve_findings", [])) for _, data in assets)
    high = sum(any(7.0 <= c.get("cvss", 0.0) < 9.0 for c in data.get("cve_findings", [])) for _, data in assets)
    medium = sum(data.get("risk_severity") == "MEDIUM" for _, data in assets)
    low = sum(data.get("risk_severity") == "LOW" for _, data in assets)

    return {
        "assets": len(assets),
        "servers": servers,
        "services": services,
        "other_devices": other,
        "average_risk": round(sum(risks) / len(risks), 1) if risks else 0.0,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


def build_executive_report_text(
    G: nx.DiGraph,
    risk_score: float,
    blast_details: Dict[str, Any],
    overall_risk: Dict[str, Any],
    scan_history: List[Dict[str, Any]],
) -> str:
    """Build formatted plaintext executive assessment report for download."""
    metrics = get_asset_metrics(G)
    lines = []
    lines.append("ACDS SECURITY ASSESSMENT")
    lines.append("=" * 40)
    lines.append("SIMULATION ONLY — NO REAL ATTACK TRAFFIC GENERATED")
    lines.append("PASSIVE SCANNING ONLY — NO EXPLOITATION PERFORMED")
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append(f"Assets Discovered: {metrics['assets']}")
    lines.append(f"Critical Findings (CVSS >= 9): {metrics['critical']}")
    lines.append(f"High Findings (CVSS 7-8.9): {metrics['high']}")
    lines.append(f"Average Asset Risk: {metrics['average_risk']}/100")
    lines.append("")
    lines.append("TOP RISKS")
    ranked = sorted(G.nodes(data=True), key=lambda x: x[1].get('risk_score', 0.0), reverse=True)[:5]
    for node, d in ranked:
        lines.append(f"  - {d.get('display_name', node)} ({d.get('ip')}): {d.get('risk_score',0)}/100 [{d.get('risk_severity','?')}]")
    lines.append("")
    lines.append("RECOMMENDED ACTIONS")
    seen = set()
    for node, d in G.nodes(data=True):
        for fix in d.get('fixes', [])[:2]:
            if fix not in seen:
                seen.add(fix)
                lines.append(f"  - {fix}")
    lines.append("")
    lines.append(f"Risk Before Defense: {risk_score if risk_score else 'Simulation not run'}")
    lines.append(f"Network Blast Radius: {blast_details.get('spread','N/A')}% spread, "
                 f"{blast_details.get('critical_assets_reached','N/A')} critical asset(s) reached")
    lines.append(f"Overall ACDS Risk: {overall_risk.get('overall_score')} ({overall_risk.get('status')})")
    lines.append("")
    if scan_history:
        lines.append("SCAN HISTORY")
        for h in scan_history:
            lines.append(f"  Scan #{h['scan_id']} — {h['asset_count']} assets, avg risk {h['average_risk']}, "
                         f"{h['critical_count']}C/{h['high_count']}H/{h['medium_count']}M/{h['low_count']}L")
    return "\n".join(lines)
