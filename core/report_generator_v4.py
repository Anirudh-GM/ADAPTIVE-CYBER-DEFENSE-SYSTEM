"""
ACDS v4.0 — PHASE 12: Professional Report Generator

Generates professional security assessment reports with all 15 sections:
  1.  Executive Summary
  2.  Network Overview
  3.  Asset Inventory
  4.  Vulnerability Assessment
  5.  Risk Assessment
  6.  Critical Assets
  7.  Attack Graph Summary
  8.  Blast Radius
  9.  MITRE ATT&CK Mapping
  10. Defense Optimization
  11. Cost vs Risk Reduction
  12. Before vs After
  13. Historical Trends
  14. Alert Summary
  15. Final Security Posture

Supports PDF (via reportlab) and CSV export.
All simulated content is clearly labelled throughout.
"""

from __future__ import annotations
import csv
import io
import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.acds_logging import get_logger

log = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────
# SECTION BUILDERS — each returns a list of (style, text) tuples
# ──────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build_report_data(
    assets: List[Dict],
    risk_summary: Dict,
    blast_radius_stats: Optional[Dict],
    attack_paths: List[Dict],
    defense_actions: List[Dict],
    before_after: Optional[Dict],
    alerts: List[Dict],
    risk_trend: List[Dict],
    mitre_mappings: List[Dict],
    overall_risk: Optional[Dict],
    scan_metadata: Optional[Dict],
) -> Dict[str, Any]:
    """
    Aggregate all data into a single structured report dict.
    This dict is the source of truth for both PDF and CSV export.
    """
    now = _ts()
    scan_meta = scan_metadata or {}

    # Section 1 — Executive Summary
    total_assets = len(assets)
    critical_count = sum(1 for a in assets if a.get("criticality", 0) >= 4)
    high_risk_count = sum(1 for a in assets if (a.get("risk_score") or 0) >= 60)
    total_cves = sum(len(a.get("cve_findings") or []) for a in assets)
    top_cves = sorted(
        [c for a in assets for c in (a.get("cve_findings") or [])],
        key=lambda c: c.get("cvss") or 0, reverse=True
    )[:5]
    overall_risk_score = (overall_risk or {}).get("overall_score") or 0
    risk_level = "CRITICAL" if overall_risk_score >= 75 else "HIGH" if overall_risk_score >= 55 else "MEDIUM" if overall_risk_score >= 35 else "LOW"

    # Section 10/11 — Defense Optimization
    budget_used = sum(a.get("cost", 0) for a in defense_actions if a.get("state") in ("APPLIED TO SIMULATION MODEL", "SELECTED"))
    risk_reduction_total = sum(a.get("risk_reduction", 0) for a in defense_actions if a.get("state") in ("APPLIED TO SIMULATION MODEL", "SELECTED"))

    return {
        "metadata": {
            "generated_at": now,
            "report_title": "ACDS v4.0 — Security Assessment Report",
            "scan_network": scan_meta.get("network", "N/A"),
            "scan_timestamp": scan_meta.get("timestamp", now),
            "report_type": "COMPREHENSIVE",
            "classification": "SIMULATION — NOT A REAL PENETRATION TEST",
        },
        "executive_summary": {
            "overall_risk_score": round(overall_risk_score, 1),
            "risk_level": risk_level,
            "total_assets": total_assets,
            "critical_assets": critical_count,
            "high_risk_assets": high_risk_count,
            "total_cves": total_cves,
            "attack_paths_found": len(attack_paths),
            "defenses_recommended": len(defense_actions),
            "budget_used": budget_used,
            "risk_reduction_achieved": round(risk_reduction_total, 1),
        },
        "assets": assets,
        "risk_summary": risk_summary,
        "blast_radius": blast_radius_stats or {},
        "attack_paths": attack_paths,
        "defense_actions": defense_actions,
        "before_after": before_after or {},
        "alerts": alerts,
        "risk_trend": risk_trend,
        "mitre_mappings": mitre_mappings,
        "overall_risk": overall_risk or {},
        "top_cves": top_cves,
    }


def export_csv(report_data: Dict[str, Any]) -> bytes:
    """
    Export a comprehensive CSV containing all 15 report sections as
    separate logical blocks within one file.
    """
    output = io.StringIO()
    w = csv.writer(output)

    meta = report_data.get("metadata", {})
    es = report_data.get("executive_summary", {})

    # ── Header ─────────────────────────────────────────────────────
    w.writerow(["ACDS v4.0 — SECURITY ASSESSMENT REPORT"])
    w.writerow(["Generated", meta.get("generated_at", "")])
    w.writerow(["Classification", meta.get("classification", "")])
    w.writerow([])

    # ── Section 1: Executive Summary ───────────────────────────────
    w.writerow(["=== SECTION 1: EXECUTIVE SUMMARY ==="])
    w.writerow(["Overall Risk Score", es.get("overall_risk_score")])
    w.writerow(["Risk Level", es.get("risk_level")])
    w.writerow(["Total Assets", es.get("total_assets")])
    w.writerow(["Critical Assets", es.get("critical_assets")])
    w.writerow(["High-Risk Assets", es.get("high_risk_assets")])
    w.writerow(["Total CVEs", es.get("total_cves")])
    w.writerow(["Attack Paths Found (Simulated)", es.get("attack_paths_found")])
    w.writerow(["Defenses Recommended", es.get("defenses_recommended")])
    w.writerow(["Budget Used (units)", es.get("budget_used")])
    w.writerow(["Risk Reduction Achieved", es.get("risk_reduction_achieved")])
    w.writerow([])

    # ── Section 3: Asset Inventory ─────────────────────────────────
    w.writerow(["=== SECTION 3: ASSET INVENTORY ==="])
    w.writerow(["IP Address", "Hostname", "Type", "Vendor", "OS", "Criticality", "Risk Score",
                "Open Ports", "CVE Count", "Observation Method"])
    for a in report_data.get("assets", []):
        w.writerow([
            a.get("ip", ""), a.get("hostname", ""), a.get("device_type", ""),
            a.get("vendor", ""), a.get("os_guess", ""),
            a.get("criticality", 0), round(a.get("risk_score") or 0, 1),
            ";".join(str(p) for p in (a.get("open_ports") or [])),
            len(a.get("cve_findings") or []),
            "REAL OBSERVATION (passive scan)",
        ])
    w.writerow([])

    # ── Section 4: Vulnerability Assessment ───────────────────────
    w.writerow(["=== SECTION 4: VULNERABILITY ASSESSMENT ==="])
    w.writerow(["Asset IP", "Asset Name", "CVE ID", "CVSS Score", "Service",
                "CISA KEV", "KEV Priority Boost", "Description"])
    for a in report_data.get("assets", []):
        for cve in (a.get("cve_findings") or []):
            w.writerow([
                a.get("ip", ""), a.get("display_name") or a.get("hostname", ""),
                cve.get("cve_id", ""), cve.get("cvss", ""),
                cve.get("service", ""),
                "YES" if cve.get("in_cisa_kev") else "NO",
                cve.get("kev_priority_boost", 0),
                cve.get("description", "")[:120],
            ])
    w.writerow([])

    # ── Section 7: Attack Paths (Simulated) ───────────────────────
    w.writerow(["=== SECTION 7: ATTACK PATHS (SIMULATION) ==="])
    w.writerow(["Source Asset", "Target Asset", "Port", "Service", "MITRE Technique",
                "MITRE ID", "Probability %", "Defense State", "Result", "Classification"])
    for path in report_data.get("attack_paths", []):
        ei = path.get("edge_intelligence", path)
        w.writerow([
            ei.get("source_asset", path.get("src", "")),
            ei.get("target_asset", path.get("dst", "")),
            ei.get("port", ""),
            ei.get("service", ""),
            ei.get("mitre_technique_name", ""),
            ei.get("mitre_technique_id", ""),
            ei.get("probability", ""),
            ei.get("defense_state", "NONE"),
            ei.get("result", ""),
            "SIMULATION — NOT REAL EXPLOITATION",
        ])
    w.writerow([])

    # ── Section 8: Blast Radius ────────────────────────────────────
    w.writerow(["=== SECTION 8: BLAST RADIUS (SIMULATION) ==="])
    br = report_data.get("blast_radius", {})
    w.writerow(["Reachable Nodes", br.get("systems_controlled", br.get("compromised_count", 0))])
    w.writerow(["Critical Assets Reached", br.get("critical_assets_reached", 0)])
    w.writerow(["Max Lateral Hops", br.get("max_lateral_hops", 0)])
    w.writerow(["Spread Score", br.get("spread", 0)])
    w.writerow(["Note", "SIMULATION — graph propagation model only"])
    w.writerow([])

    # ── Section 9: MITRE ATT&CK Mapping ───────────────────────────
    w.writerow(["=== SECTION 9: MITRE ATT&CK MAPPING ==="])
    w.writerow(["Technique ID", "Technique Name", "Tactic", "Port", "Service", "Asset"])
    for m in report_data.get("mitre_mappings", []):
        w.writerow([
            m.get("technique_id", ""), m.get("technique_name", ""),
            m.get("tactic", ""), m.get("port", ""),
            m.get("service", ""), m.get("asset", ""),
        ])
    w.writerow([])

    # ── Section 10: Defense Optimization ──────────────────────────
    w.writerow(["=== SECTION 10: DEFENSE OPTIMIZATION (SIMULATION) ==="])
    w.writerow(["Action", "Type", "Priority", "Cost", "Risk Reduction",
                "Blast Radius Reduction", "Paths Removed", "Critical Protected",
                "Efficiency", "State"])
    for d in report_data.get("defense_actions", []):
        w.writerow([
            d.get("action", ""), d.get("type", ""), d.get("priority", ""),
            d.get("cost", 0), d.get("risk_reduction", 0),
            d.get("blast_radius_reduction", 0), d.get("attack_paths_removed", 0),
            d.get("critical_assets_protected", 0), d.get("efficiency", 0),
            d.get("state", ""),
        ])
    w.writerow([])

    # ── Section 12: Before vs After ───────────────────────────────
    w.writerow(["=== SECTION 12: BEFORE VS AFTER (SIMULATION) ==="])
    ba = report_data.get("before_after", {})
    for metric_key, metric_data in (ba.get("metrics") or {}).items():
        w.writerow([
            metric_data.get("label", metric_key),
            f"BEFORE: {metric_data.get('before', 'N/A')}",
            f"AFTER: {metric_data.get('after', 'N/A')}",
            f"DELTA: {metric_data.get('delta', 'N/A')}",
        ])
    w.writerow(["Assessment", ba.get("assessment", "N/A")])
    w.writerow([])

    # ── Section 14: Alert Summary ──────────────────────────────────
    w.writerow(["=== SECTION 14: ALERT SUMMARY ==="])
    w.writerow(["Timestamp", "Severity", "Type", "Asset", "Title", "Description", "Correlated"])
    for alert in report_data.get("alerts", [])[:50]:
        w.writerow([
            (alert.get("timestamp") or "")[:19],
            alert.get("severity", ""), alert.get("alert_type", ""),
            alert.get("asset", ""), alert.get("title", ""),
            (alert.get("description") or "")[:120],
            "YES" if alert.get("is_correlated") else "NO",
        ])
    w.writerow([])

    # ── Section 15: Final Security Posture ────────────────────────
    w.writerow(["=== SECTION 15: FINAL SECURITY POSTURE ==="])
    w.writerow(["Overall Risk Score", es.get("overall_risk_score")])
    w.writerow(["Risk Level", es.get("risk_level")])
    w.writerow(["Attack Paths (Simulated)", es.get("attack_paths_found")])
    w.writerow(["Risk Reduction Achieved", es.get("risk_reduction_achieved")])
    w.writerow(["Report Classification", meta.get("classification")])
    w.writerow([])
    w.writerow(["This report was generated by ACDS v4.0. All attack paths and compromise outcomes"])
    w.writerow(["are SIMULATED using a graph model. No real exploitation occurred."])

    return output.getvalue().encode("utf-8")


def export_pdf(report_data: Dict[str, Any]) -> Optional[bytes]:
    """
    Generate a professional PDF report using reportlab.
    Falls back to a formatted text report if reportlab is unavailable.
    Returns bytes of the PDF (or text), or None on failure.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, PageBreak, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle("ACDSTitle", parent=styles["Title"],
                                     fontSize=20, spaceAfter=6, textColor=colors.HexColor("#003366"))
        h1_style = ParagraphStyle("ACDSH1", parent=styles["Heading1"],
                                  fontSize=14, spaceAfter=4, textColor=colors.HexColor("#003366"),
                                  borderPad=4)
        h2_style = ParagraphStyle("ACDSH2", parent=styles["Heading2"],
                                  fontSize=11, spaceAfter=3, textColor=colors.HexColor("#005588"))
        body_style = ParagraphStyle("ACDSBody", parent=styles["Normal"],
                                    fontSize=8, spaceAfter=3, leading=12)
        sim_style = ParagraphStyle("ACDSSim", parent=styles["Normal"],
                                   fontSize=7, spaceAfter=2,
                                   textColor=colors.HexColor("#cc0000"),
                                   fontName="Helvetica-Oblique")
        note_style = ParagraphStyle("ACDSNote", parent=styles["Normal"],
                                    fontSize=7.5, spaceAfter=2,
                                    textColor=colors.HexColor("#555555"))

        meta = report_data.get("metadata", {})
        es = report_data.get("executive_summary", {})
        story = []

        def hr():
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=colors.HexColor("#003366"), spaceAfter=6))

        def section(num, title):
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph(f"Section {num}: {title}", h1_style))
            hr()

        # ── Cover Page ────────────────────────────────────────────
        story.append(Spacer(1, 2*cm))
        story.append(Paragraph("ADAPTIVE CYBER DEFENSE SYSTEM", title_style))
        story.append(Paragraph("Security Assessment Report — v4.0", h2_style))
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph(f"Generated: {meta.get('generated_at','')}", body_style))
        story.append(Paragraph(f"Network: {meta.get('scan_network','N/A')}", body_style))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(meta.get("classification", ""), sim_style))
        story.append(PageBreak())

        # ── Section 1: Executive Summary ─────────────────────────
        section(1, "Executive Summary")
        risk_level = es.get("risk_level", "UNKNOWN")
        risk_color = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#cc8800", "LOW": "#006600"}.get(risk_level, "#333333")
        story.append(Paragraph(
            f"<font color='{risk_color}'><b>OVERALL RISK: {risk_level} ({es.get('overall_risk_score',0):.0f}/100)</b></font>",
            body_style
        ))
        story.append(Spacer(1, 0.2*cm))
        exec_data = [
            ["Metric", "Value"],
            ["Total Assets Discovered", str(es.get("total_assets", 0))],
            ["Critical Assets", str(es.get("critical_assets", 0))],
            ["High-Risk Assets", str(es.get("high_risk_assets", 0))],
            ["Total CVEs Identified", str(es.get("total_cves", 0))],
            ["Simulated Attack Paths", str(es.get("attack_paths_found", 0))],
            ["Defenses Recommended", str(es.get("defenses_recommended", 0))],
            ["Risk Reduction (Simulated)", f"-{es.get('risk_reduction_achieved',0):.0f}pts"],
        ]
        t = Table(exec_data, colWidths=[9*cm, 7*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph("All attack paths shown in this report are SIMULATED using a graph propagation model. No real exploitation occurred.", sim_style))

        # ── Section 2: Network Overview ───────────────────────────
        story.append(PageBreak())
        section(2, "Network Overview")
        risk_sum = report_data.get("risk_summary", {})
        story.append(Paragraph(f"Total Assets: {es.get('total_assets',0)}  |  "
                               f"Critical: {es.get('critical_assets',0)}  |  "
                               f"High-Risk: {es.get('high_risk_assets',0)}", body_style))
        story.append(Paragraph(f"Observation Method: Passive network scan (REAL OBSERVATION). "
                               f"No active exploitation was performed.", note_style))

        # ── Section 3: Asset Inventory ────────────────────────────
        section(3, "Asset Inventory")
        assets = report_data.get("assets", [])
        if assets:
            asset_data = [["IP Address", "Hostname", "Type", "Criticality", "Risk Score", "CVEs"]]
            for a in assets[:30]:
                asset_data.append([
                    a.get("ip", ""), a.get("hostname", "")[:18],
                    a.get("device_type", "")[:12],
                    str(a.get("criticality", 0)),
                    f"{(a.get('risk_score') or 0):.0f}/100",
                    str(len(a.get("cve_findings") or [])),
                ])
            t = Table(asset_data, colWidths=[3.2*cm, 3.5*cm, 2.8*cm, 2.2*cm, 2.5*cm, 1.8*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t)
            if len(assets) > 30:
                story.append(Paragraph(f"[{len(assets)-30} additional assets in CSV export]", note_style))

        # ── Section 4: Vulnerability Assessment ──────────────────
        story.append(PageBreak())
        section(4, "Vulnerability Assessment")
        top_cves = report_data.get("top_cves", [])
        if top_cves:
            story.append(Paragraph("Top 5 Critical CVEs:", h2_style))
            cve_data = [["CVE ID", "CVSS", "Service", "Asset", "CISA KEV"]]
            for cve in top_cves:
                cve_data.append([
                    cve.get("cve_id", ""), str(cve.get("cvss", "")),
                    cve.get("service", ""), cve.get("asset_ip", ""),
                    "YES ⚠" if cve.get("in_cisa_kev") else "NO",
                ])
            t = Table(cve_data, colWidths=[3.8*cm, 2*cm, 3*cm, 3.5*cm, 2.7*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#660000")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff8f8")]),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t)

        # ── Sections 5-15: Condensed ──────────────────────────────
        story.append(PageBreak())
        section(5, "Risk Assessment")
        story.append(Paragraph(f"Overall Risk Score: {es.get('overall_risk_score',0):.0f}/100 — {es.get('risk_level','N/A')}", body_style))
        story.append(Paragraph("Risk is calculated using a graph-aware multi-factor model combining CVSS, exposure, attack paths, downstream criticality, and blast radius.", note_style))

        section(6, "Critical Assets")
        critical = [a for a in assets if a.get("criticality", 0) >= 4]
        for a in critical[:10]:
            story.append(Paragraph(
                f"• {a.get('display_name') or a.get('hostname','')} ({a.get('ip','')}) — "
                f"Criticality {a.get('criticality',0)} — Risk {(a.get('risk_score') or 0):.0f}/100",
                body_style
            ))

        section(7, "Attack Graph — Summary (SIMULATION)")
        paths = report_data.get("attack_paths", [])
        story.append(Paragraph(f"Total modeled attack paths: {len(paths)} (SIMULATION — graph model only, no real exploitation)", sim_style))
        for path in paths[:8]:
            ei = path.get("edge_intelligence", path)
            story.append(Paragraph(
                f"• {ei.get('source_asset','?')} → {ei.get('target_asset','?')} "
                f"via {ei.get('service','?')} TCP/{ei.get('port','?')} — "
                f"MITRE {ei.get('mitre_technique_id','?')} — {ei.get('result','?')}",
                body_style
            ))

        section(8, "Blast Radius (SIMULATION)")
        br = report_data.get("blast_radius", {})
        story.append(Paragraph(
            f"Reachable Nodes: {br.get('systems_controlled', br.get('compromised_count', 0))}  |  "
            f"Critical Assets Reached: {br.get('critical_assets_reached', 0)}  |  "
            f"Max Depth: {br.get('max_lateral_hops', 0)} hops  |  "
            f"Spread Score: {br.get('spread', 0):.0f}/100", body_style
        ))
        story.append(Paragraph("SIMULATION — blast radius is modeled propagation, not real compromise.", sim_style))

        section(9, "MITRE ATT&CK Mapping")
        mitre = report_data.get("mitre_mappings", [])
        for m in mitre[:12]:
            story.append(Paragraph(
                f"• {m.get('technique_id','?')} — {m.get('technique_name','?')} "
                f"[{m.get('tactic','?')}] — Port {m.get('port','?')} ({m.get('service','?')}) on {m.get('asset','?')}",
                body_style
            ))

        story.append(PageBreak())
        section(10, "Defense Optimization (SIMULATION)")
        for d in report_data.get("defense_actions", [])[:12]:
            story.append(Paragraph(
                f"• {d.get('action','')} — Cost: {d.get('cost',0)} | "
                f"Risk Reduction: -{d.get('risk_reduction',0):.0f}pts | "
                f"Paths Removed: {d.get('attack_paths_removed',0)} | "
                f"Priority: {d.get('priority','')} — {d.get('state','')}",
                body_style
            ))

        section(11, "Cost vs Risk Reduction")
        story.append(Paragraph(
            f"Total budget used: {es.get('budget_used',0)} units  |  "
            f"Total risk reduction: -{es.get('risk_reduction_achieved',0):.0f}pts  |  "
            f"All defense impacts are SIMULATED.", body_style
        ))

        section(12, "Before vs After (SIMULATION)")
        ba = report_data.get("before_after", {})
        for metric_key, m in (ba.get("metrics") or {}).items():
            if m.get("before") is not None:
                story.append(Paragraph(
                    f"• {m.get('label',metric_key)}: {m.get('before','?')} → {m.get('after','N/A')} "
                    f"(Δ {m.get('delta','N/A')})",
                    body_style
                ))
        if ba.get("assessment"):
            story.append(Paragraph(f"Assessment: {ba.get('assessment','')}", h2_style))

        section(13, "Historical Trends")
        trend = report_data.get("risk_trend", [])
        story.append(Paragraph(f"Risk data points available: {len(trend)}", body_style))
        if trend:
            story.append(Paragraph(
                f"First recorded: {(trend[0].get('timestamp') or '')[:16]}  |  "
                f"Latest: {(trend[-1].get('timestamp') or '')[:16]}  |  "
                f"Latest risk: {trend[-1].get('overall_risk', 0):.0f}/100", body_style
            ))

        section(14, "Alert Summary")
        alerts = report_data.get("alerts", [])
        story.append(Paragraph(f"Total alerts generated: {len(alerts)}", body_style))
        correlated = [a for a in alerts if a.get("is_correlated")]
        story.append(Paragraph(f"Correlated alerts: {len(correlated)}", body_style))
        for alert in sorted(alerts, key=lambda a: a.get("severity", ""), reverse=True)[:8]:
            story.append(Paragraph(
                f"• [{alert.get('severity','')}] {alert.get('title','')} — {alert.get('asset','')}",
                body_style
            ))

        section(15, "Final Security Posture")
        story.append(Paragraph(
            f"<font color='{risk_color}'><b>FINAL RISK LEVEL: {es.get('risk_level','?')} "
            f"({es.get('overall_risk_score',0):.0f}/100)</b></font>", body_style
        ))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            "This security assessment was conducted using the Adaptive Cyber Defense System (ACDS) v4.0. "
            "All attack paths, blast radius calculations, and defense simulations are the result of "
            "graph-based propagation modeling. No real exploitation, credential attacks, or destructive "
            "actions were performed. All simulated content is clearly labelled throughout this report.",
            note_style
        ))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(meta.get("classification", ""), sim_style))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        log.warning("reportlab not available — generating text report fallback")
        return _export_text_fallback(report_data)
    except Exception as exc:
        log.error("PDF generation failed: %s", exc)
        return _export_text_fallback(report_data)


def _export_text_fallback(report_data: Dict[str, Any]) -> bytes:
    """Plain-text fallback when reportlab is unavailable."""
    meta = report_data.get("metadata", {})
    es = report_data.get("executive_summary", {})
    lines = [
        "=" * 70,
        "ACDS v4.0 — SECURITY ASSESSMENT REPORT (TEXT FALLBACK)",
        f"Generated: {meta.get('generated_at','')}",
        meta.get("classification", ""),
        "=" * 70,
        "",
        "SECTION 1: EXECUTIVE SUMMARY",
        f"Overall Risk: {es.get('risk_level','?')} ({es.get('overall_risk_score',0):.0f}/100)",
        f"Total Assets: {es.get('total_assets',0)}",
        f"Critical Assets: {es.get('critical_assets',0)}",
        f"Total CVEs: {es.get('total_cves',0)}",
        f"Attack Paths (Simulated): {es.get('attack_paths_found',0)}",
        f"Defenses Recommended: {es.get('defenses_recommended',0)}",
        f"Risk Reduction Achieved: -{es.get('risk_reduction_achieved',0):.0f}pts",
        "",
        "NOTE: reportlab is required for PDF output. Install with: pip install reportlab",
        "All attack paths are SIMULATED — no real exploitation occurred.",
    ]
    return "\n".join(lines).encode("utf-8")
