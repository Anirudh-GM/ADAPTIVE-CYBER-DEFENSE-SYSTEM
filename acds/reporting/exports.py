"""
ACDS Data Export Engine
Exports network asset inventories and deduplicated/prioritized vulnerability findings into standardized CSV files.
"""

import csv
import io
from typing import Dict, List, Optional, Any
import networkx as nx

from acds.vulnerability.deduplication import deduplicate_findings
from acds.vulnerability.prioritization import prioritize_findings


def export_asset_inventory_csv(G: nx.DiGraph) -> str:
    """Generate CSV string of network asset inventory."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'IP', 'Hostname', 'MAC', 'Vendor', 'OS', 'OS Confidence', 'Device Type',
        'Device Confidence', 'Services', 'Ports', 'Risk', 'Criticality'
    ])
    for node, d in G.nodes(data=True):
        writer.writerow([
            d.get('ip', ''),
            d.get('hostname') or 'Unknown',
            d.get('mac') or 'Unknown',
            d.get('mac_vendor') or 'Unknown',
            d.get('os', 'unknown'),
            f"{int((d.get('os_confidence') or 0) * 100)}%" if d.get('os_confidence') is not None else 'N/A',
            d.get('device_type', 'Unknown'),
            f"{int((d.get('device_confidence') or 0) * 100)}%" if d.get('device_confidence') is not None else 'N/A',
            '; '.join(d.get('services', [])),
            '; '.join(str(p) for p in d.get('open_ports', [])),
            f"{d.get('risk_score', 0)}/100 ({d.get('risk_severity','?')})",
            d.get('criticality_label', 'Unknown'),
        ])
    return buf.getvalue()


def export_vulnerability_report_csv(
    G: nx.DiGraph,
    vulnerabilities: Optional[List[Any]] = None,
) -> str:
    """Generate CSV string of confirmed, deduplicated, and prioritized vulnerability findings."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'Priority', 'Priority Score', 'Asset', 'CVE', 'CVSS', 'Severity', 'Product', 'Version',
        'Description', 'Recommendation', 'Detection Confidence', 'Published', 'Modified',
        'Source', 'Occurrence Count', 'Attack Path Exposure', 'Finding Status'
    ])

    if vulnerabilities is not None:
        for v in vulnerabilities:
            aff_assets = [a.host for a in getattr(v, "affected_assets", {}).values()]
            on_path = any(getattr(a, "on_attack_path", False) for a in getattr(v, "affected_assets", {}).values())
            writer.writerow([
                getattr(v, "priority_level", "P4"),
                getattr(v, "priority_score", 0.0),
                '; '.join(aff_assets) or "Network",
                getattr(v, "cve_id", ""),
                getattr(v, "cvss", 0.0),
                getattr(v, "severity", ""),
                getattr(v, "product", ""),
                getattr(v, "version", "") or 'Unknown',
                getattr(v, "description", ""),
                getattr(v, "recommendation", ""),
                "High" if getattr(v, "is_cve", True) else "Medium",
                "N/A",
                "N/A",
                getattr(v, "source", ""),
                getattr(v, "total_occurrences", 1),
                "YES" if on_path else "NO",
                getattr(v, "remediation_status", "ACTIVE"),
            ])
    else:
        # Fallback to direct graph node iteration while populating all columns
        for node, d in G.nodes(data=True):
            fixes = d.get('fixes', [])
            for i, c in enumerate(d.get('cve_findings', [])):
                rec = fixes[i] if i < len(fixes) else (fixes[0] if fixes else 'See generic remediation guidance')
                cvss_val = c.get('cvss', 0.0)
                prio_lvl = "P1" if cvss_val >= 9.0 else "P2" if cvss_val >= 7.0 else "P3" if cvss_val >= 4.0 else "P4"
                writer.writerow([
                    prio_lvl,
                    round(cvss_val * 10.0, 1),
                    d.get('display_name', node),
                    c.get('cve_id'),
                    c.get('cvss'),
                    c.get('severity'),
                    c.get('affected_product'),
                    c.get('detected_version') or 'Unknown',
                    c.get('summary'),
                    rec,
                    c.get('detection_confidence'),
                    c.get('published'),
                    c.get('modified'),
                    c.get('source'),
                    1,
                    "NO",
                    "ACTIVE",
                ])

    return buf.getvalue()
