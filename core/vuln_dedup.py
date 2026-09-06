"""
VULNERABILITY DEDUPLICATION — core/vuln_dedup.py
─────────────────────────────────────────────────────────────────
Priority 8/10 (explicit "IMPORTANT" callout in the spec): the
existing app already stores CVE findings per-node
(node['cve_findings']), which is correct for per-asset detail, but
the "ALL CONFIRMED CVEs" panel lists one row per (asset, CVE) pair
with no grouping — the same CVE on 3 servers shows as 3 unrelated
rows.

This module groups findings by a logical dedup key:
    (cve_id, service, detection_source)
so the same CVE on the same service, found the same way, becomes
ONE row with an "Affected Assets" list/count, while still keeping
enough detail (which assets, which evidence) not to lose information.
"""


def deduplicate_findings(G):
    """G: the live NetworkX graph (node data must include 'ip',
    'display_name', and 'cve_findings' as produced by app.py).

    Returns a list of grouped findings, sorted by max CVSS desc:
      {
        'cve_id':.., 'cvss':.., 'severity':.., 'summary':..,
        'service':.., 'detection_source':..,
        'affected_assets': [ {'node':.., 'ip':.., 'display_name':.., 'detected_version':..}, ... ],
        'affected_count': int,
      }
    """
    groups = {}
    for node, data in G.nodes(data=True):
        if data.get("node_type") == "honeypot":
            continue
        for c in data.get("cve_findings", []):
            key = (c.get("cve_id"), c.get("service"), c.get("detection_source") or c.get("cve_source"))
            if key not in groups:
                groups[key] = {
                    "cve_id": c.get("cve_id"),
                    "cvss": c.get("cvss"),
                    "severity": c.get("severity"),
                    "summary": c.get("summary"),
                    "service": c.get("service"),
                    "detection_source": c.get("detection_source") or c.get("cve_source"),
                    "affected_assets": [],
                }
            groups[key]["affected_assets"].append({
                "node": node,
                "ip": data.get("ip"),
                "display_name": data.get("display_name") or node,
                "detected_version": c.get("detected_version"),
            })

    result = []
    for g in groups.values():
        g["affected_count"] = len(g["affected_assets"])
        result.append(g)

    result.sort(key=lambda g: (g["cvss"] or 0), reverse=True)
    return result
