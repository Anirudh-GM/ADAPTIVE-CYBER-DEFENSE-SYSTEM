"""
CHANGE DETECTION ENGINE — core/change_detector.py
─────────────────────────────────────────────────────────────────
Priority 13 (mandatory): compares the CURRENT scan snapshot against
the PREVIOUS persisted snapshot (from data/database.py) instead of
treating every scan as independent.

This module is pure logic — it takes two lists of asset-snapshot
dicts (the shape produced by database.get_snapshot / the shape you
build from the live graph) and returns a structured diff. It does
not touch Streamlit or the graph directly, so it's easy to unit
test and reuse from any UI section.

Dedup/match key: IP address is the primary match key (stable within
one LAN scan session), with MAC as a secondary signal surfaced in
the "changed" evidence when IP reassignment is suspected (DHCP churn).
"""


def _asset_by_ip(assets):
    return {a["ip"]: a for a in assets if a.get("ip")}


def diff_scans(previous_assets, current_assets):
    """Compare two lists of asset dicts (each with at least: ip, mac,
    hostname, device_type, os_type, criticality, risk_score,
    risk_severity, open_ports (list[int]), services (list[str]),
    cve_ids (list[str])).

    Returns a dict:
      {
        'new_assets': [ip, ...],
        'missing_assets': [ip, ...],
        'changed_assets': [
            {
              'ip': ..., 'hostname': ...,
              'changes': [ {'field': 'open_ports', 'before': [...], 'after': [...]}, ... ],
              'risk_before': .., 'risk_after': .., 'risk_delta': ..
            }, ...
        ],
        'new_vulnerabilities': [ {'ip':.., 'cve_id':..}, ... ],
        'resolved_vulnerabilities': [ {'ip':.., 'cve_id':..}, ... ],
        'has_baseline': bool,   # False if there was no previous scan to compare
      }
    """
    if not previous_assets:
        return {
            "new_assets": [a["ip"] for a in current_assets],
            "missing_assets": [],
            "changed_assets": [],
            "new_vulnerabilities": [],
            "resolved_vulnerabilities": [],
            "has_baseline": False,
        }

    prev_by_ip = _asset_by_ip(previous_assets)
    curr_by_ip = _asset_by_ip(current_assets)

    prev_ips = set(prev_by_ip.keys())
    curr_ips = set(curr_by_ip.keys())

    new_assets = sorted(curr_ips - prev_ips)
    missing_assets = sorted(prev_ips - curr_ips)
    common_ips = curr_ips & prev_ips

    changed_assets = []
    new_vulns = []
    resolved_vulns = []

    for ip in sorted(common_ips):
        before = prev_by_ip[ip]
        after = curr_by_ip[ip]
        changes = []

        for field in ("hostname", "device_type", "os_type", "criticality"):
            if (before.get(field) or None) != (after.get(field) or None):
                changes.append({"field": field, "before": before.get(field), "after": after.get(field)})

        before_ports = set(before.get("open_ports") or [])
        after_ports = set(after.get("open_ports") or [])
        opened = sorted(after_ports - before_ports)
        closed = sorted(before_ports - after_ports)
        if opened:
            changes.append({"field": "ports_opened", "before": None, "after": opened})
        if closed:
            changes.append({"field": "ports_closed", "before": closed, "after": None})

        before_services = set(before.get("services") or [])
        after_services = set(after.get("services") or [])
        if before_services != after_services:
            changes.append({
                "field": "services",
                "before": sorted(before_services - after_services) or None,
                "after": sorted(after_services - before_services) or None,
            })

        risk_before = before.get("risk_score")
        risk_after = after.get("risk_score")
        risk_delta = None
        if risk_before is not None and risk_after is not None:
            risk_delta = round(risk_after - risk_before, 1)
            if abs(risk_delta) >= 0.1:
                changes.append({"field": "risk_score", "before": risk_before, "after": risk_after})

        before_cves = set(before.get("cve_ids") or [])
        after_cves = set(after.get("cve_ids") or [])
        for cve in sorted(after_cves - before_cves):
            new_vulns.append({"ip": ip, "hostname": after.get("hostname"), "cve_id": cve})
        for cve in sorted(before_cves - after_cves):
            resolved_vulns.append({"ip": ip, "hostname": before.get("hostname"), "cve_id": cve})
        if (after_cves - before_cves) or (before_cves - after_cves):
            changes.append({
                "field": "vulnerabilities",
                "before": sorted(before_cves - after_cves) or None,
                "after": sorted(after_cves - before_cves) or None,
            })

        if changes:
            changed_assets.append({
                "ip": ip,
                "hostname": after.get("hostname") or before.get("hostname"),
                "changes": changes,
                "risk_before": risk_before,
                "risk_after": risk_after,
                "risk_delta": risk_delta,
            })

    # Assets that vanished may also represent "resolved" vulnerabilities —
    # only count still-present assets above to avoid double counting; missing
    # assets are reported separately via missing_assets so nothing is lost.

    return {
        "new_assets": new_assets,
        "missing_assets": missing_assets,
        "changed_assets": changed_assets,
        "new_vulnerabilities": new_vulns,
        "resolved_vulnerabilities": resolved_vulns,
        "has_baseline": True,
    }


# ─────────────────────────────────────────────────────────────────
# SPRINT 1 — PHASE 4: structured change detection for the persistent
# monitoring pipeline (core/database.py). This is intentionally a
# SEPARATE function from diff_scans() above: diff_scans() compares
# two full scan-snapshot asset lists (data/database.py, IP-keyed,
# used by the existing "🔁 CHANGE DETECTION" panel). This function
# compares asset-identity-keyed state (core/database.py, MAC-first
# matching, persistent ONLINE/OFFLINE status) and returns the flat,
# typed change objects the Sprint 1 spec calls for. Pure comparison
# logic only — no DB or Streamlit access here.
# ─────────────────────────────────────────────────────────────────

# Ports where a newly-opened listener is treated as a bigger deal
# (remote admin / file-sharing / database protocols commonly abused
# for lateral movement or data access).
_SENSITIVE_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389,
                     5432, 5900, 6379, 9200, 27017}


def _port_severity(port):
    return "HIGH" if port in _SENSITIVE_PORTS else "MEDIUM"


def detect_asset_service_changes(before, after):
    """Compare two state snapshots and return a flat list of structured
    change objects.

    before / after shape:
        {
          "assets":   { asset_id: {"ip":.., "mac":.., "hostname":.., "status": "ONLINE"|"OFFLINE"} },
          "services": { asset_id: { port: {"service":.., "version":..} } },
        }

    Returns a list of dicts, each one of:
        {"type": "NEW_ASSET",      "asset": ip, "hostname":.., "severity":..}
        {"type": "REMOVED_ASSET",  "asset": ip, "hostname":.., "severity":..}
        {"type": "NEW_PORT",       "asset": ip, "port":.., "service":.., "severity":..}
        {"type": "CLOSED_PORT",    "asset": ip, "port":.., "service":.., "severity":..}
        {"type": "SERVICE_CHANGED","asset": ip, "port":.., "before_service":.., "after_service":.., "severity":..}
        {"type": "VERSION_CHANGED","asset": ip, "port":.., "service":.., "before_version":.., "after_version":.., "severity":..}
    """
    changes = []
    before_assets = before.get("assets", {})
    after_assets = after.get("assets", {})
    before_services = before.get("services", {})
    after_services = after.get("services", {})

    def _label(asset_id, assets_map):
        a = assets_map.get(asset_id, {})
        return a.get("ip") or a.get("hostname") or f"asset:{asset_id}"

    for asset_id, a in after_assets.items():
        if asset_id not in before_assets:
            changes.append({
                "type": "NEW_ASSET", "asset": _label(asset_id, after_assets),
                "hostname": a.get("hostname"), "severity": "MEDIUM",
            })

    for asset_id, a in before_assets.items():
        was_online = a.get("status") == "ONLINE"
        now = after_assets.get(asset_id)
        if was_online and now and now.get("status") == "OFFLINE":
            changes.append({
                "type": "REMOVED_ASSET", "asset": _label(asset_id, before_assets),
                "hostname": a.get("hostname"), "severity": "LOW",
            })

    all_asset_ids = set(before_services) | set(after_services)
    for asset_id in all_asset_ids:
        asset_ip = _label(asset_id, after_assets) if asset_id in after_assets else _label(asset_id, before_assets)
        before_ports = before_services.get(asset_id, {})
        after_ports = after_services.get(asset_id, {})

        for port, svc in after_ports.items():
            if port not in before_ports:
                changes.append({
                    "type": "NEW_PORT", "asset": asset_ip, "port": port,
                    "service": svc.get("service"), "severity": _port_severity(port),
                })
            else:
                bsvc = before_ports[port]
                if (bsvc.get("service") or None) != (svc.get("service") or None):
                    changes.append({
                        "type": "SERVICE_CHANGED", "asset": asset_ip, "port": port,
                        "before_service": bsvc.get("service"), "after_service": svc.get("service"),
                        "severity": "MEDIUM",
                    })
                elif (bsvc.get("version") or None) != (svc.get("version") or None):
                    changes.append({
                        "type": "VERSION_CHANGED", "asset": asset_ip, "port": port,
                        "service": svc.get("service"),
                        "before_version": bsvc.get("version"), "after_version": svc.get("version"),
                        "severity": "LOW",
                    })

        for port, bsvc in before_ports.items():
            if port not in after_ports:
                changes.append({
                    "type": "CLOSED_PORT", "asset": asset_ip, "port": port,
                    "service": bsvc.get("service"), "severity": "LOW",
                })

    return changes


def graph_to_asset_snapshot(G):
    """Convert the live NetworkX graph (as built by build_dynamic_graph in
    app.py) into the flat list-of-dicts shape diff_scans()/database.save_scan()
    expect. Skips honeypot decoy nodes — those aren't real discovered assets."""
    assets = []
    for node, data in G.nodes(data=True):
        if data.get("node_type") == "honeypot":
            continue
        cve_ids = sorted({c.get("cve_id") for c in data.get("cve_findings", []) if c.get("cve_id")})
        assets.append({
            "ip": data.get("ip"),
            "mac": data.get("mac"),
            "hostname": data.get("hostname"),
            "device_type": data.get("device_type"),
            "os_type": data.get("os"),
            "criticality": data.get("criticality_label"),
            "risk_score": data.get("risk_score"),
            "risk_severity": data.get("risk_severity"),
            "open_ports": list(data.get("open_ports") or []),
            "services": list(data.get("services") or []),
            "cve_ids": cve_ids,
        })
    return assets
