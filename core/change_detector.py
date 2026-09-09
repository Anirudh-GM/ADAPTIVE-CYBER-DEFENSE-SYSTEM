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


import re


def _asset_key(a):
    """Compute stable match key for an asset: normalized MAC first, then asset_id, then hostname+vendor, fallback IP."""
    mac = a.get("mac")
    if mac and mac.strip() and mac.strip().upper() not in ("UNKNOWN", "LOCAL", "NONE", "—", "-"):
        return f"MAC:{re.sub(r'[^A-Fa-f0-9]', '', mac).upper()}"
    asset_id = a.get("asset_id")
    if asset_id and asset_id.strip():
        return f"ID:{asset_id.strip()}"
    hostname = a.get("hostname")
    if hostname and hostname.strip() and hostname.lower() not in ("unknown", "none", (a.get("ip") or "").lower()):
        return f"HOST:{hostname.strip().lower()}"
    return f"IP:{a.get('ip')}"


def _asset_by_stable_id(assets):
    mapping = {}
    if isinstance(assets, dict):
        asset_list = []
        for ip, val in assets.items():
            if isinstance(val, dict):
                item = dict(val)
                if 'ip' not in item or not item['ip']:
                    item['ip'] = ip
                asset_list.append(item)
            else:
                asset_list.append({'ip': ip})
        assets = asset_list
    elif not isinstance(assets, (list, tuple)):
        assets = list(assets) if assets else []

    for a in assets:
        if isinstance(a, dict):
            key = _asset_key(a)
            mapping[key] = a
    return mapping


def diff_scans(previous_assets, current_assets):
    """Compare two lists/dicts of asset dicts using stable asset identity (MAC / asset_id).
    Detects IP_CHANGED, NEW_ASSET, REMOVED_ASSET, and service/vulnerability deltas."""
    if isinstance(current_assets, dict):
        current_list = []
        for ip, val in current_assets.items():
            if isinstance(val, dict):
                item = dict(val)
                if 'ip' not in item:
                    item['ip'] = ip
                current_list.append(item)
            else:
                current_list.append({'ip': ip})
        current_assets = current_list

    if isinstance(previous_assets, dict):
        prev_list = []
        for ip, val in previous_assets.items():
            if isinstance(val, dict):
                item = dict(val)
                if 'ip' not in item:
                    item['ip'] = ip
                prev_list.append(item)
            else:
                prev_list.append({'ip': ip})
        previous_assets = prev_list

    if not previous_assets:
        return {
            "new_assets": [a.get("ip") for a in current_assets if a.get("ip")],
            "missing_assets": [],
            "changed_assets": [],
            "ip_changed_assets": [],
            "new_vulnerabilities": [],
            "resolved_vulnerabilities": [],
            "has_baseline": False,
        }

    prev_by_key = _asset_by_stable_id(previous_assets)
    curr_by_key = _asset_by_stable_id(current_assets)

    prev_keys = set(prev_by_key.keys())
    curr_keys = set(curr_by_key.keys())

    new_keys = curr_keys - prev_keys
    missing_keys = prev_keys - curr_keys
    common_keys = curr_keys & prev_keys

    new_assets = [curr_by_key[k].get("ip") for k in sorted(new_keys) if curr_by_key[k].get("ip")]
    missing_assets = [prev_by_key[k].get("ip") for k in sorted(missing_keys) if prev_by_key[k].get("ip")]

    changed_assets = []
    ip_changed_assets = []
    new_vulns = []
    resolved_vulns = []

    for key in sorted(common_keys):
        before = prev_by_key[key]
        after = curr_by_key[key]
        changes = []

        # Check IP address change (DHCP lease update)
        old_ip = before.get("ip")
        new_ip = after.get("ip")
        if old_ip and new_ip and old_ip != new_ip:
            changes.append({"field": "ip_address", "before": old_ip, "after": new_ip})
            ip_changed_assets.append({
                "asset_id": after.get("asset_id") or before.get("asset_id") or key,
                "hostname": after.get("hostname") or before.get("hostname"),
                "mac": after.get("mac") or before.get("mac"),
                "old_ip": old_ip,
                "new_ip": new_ip,
            })

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
        current_display_ip = new_ip or old_ip
        for cve in sorted(after_cves - before_cves):
            new_vulns.append({"ip": current_display_ip, "hostname": after.get("hostname"), "cve_id": cve})
        for cve in sorted(before_cves - after_cves):
            resolved_vulns.append({"ip": current_display_ip, "hostname": before.get("hostname"), "cve_id": cve})
        if (after_cves - before_cves) or (before_cves - after_cves):
            changes.append({
                "field": "vulnerabilities",
                "before": sorted(before_cves - after_cves) or None,
                "after": sorted(after_cves - before_cves) or None,
            })

        if changes:
            changed_assets.append({
                "ip": current_display_ip,
                "asset_id": after.get("asset_id") or before.get("asset_id") or key,
                "hostname": after.get("hostname") or before.get("hostname"),
                "mac": after.get("mac") or before.get("mac"),
                "changes": changes,
                "risk_before": risk_before,
                "risk_after": risk_after,
                "risk_delta": risk_delta,
            })

    return {
        "new_assets": new_assets,
        "missing_assets": missing_assets,
        "changed_assets": changed_assets,
        "ip_changed_assets": ip_changed_assets,
        "new_vulnerabilities": new_vulns,
        "resolved_vulnerabilities": resolved_vulns,
        "has_baseline": True,
    }


# ─────────────────────────────────────────────────────────────────
# SPRINT 1 — PHASE 4: structured change detection for the persistent
# monitoring pipeline (core/database.py).
# ─────────────────────────────────────────────────────────────────

_SENSITIVE_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389,
                     5432, 5900, 6379, 9200, 27017}


def _port_severity(port):
    return "HIGH" if port in _SENSITIVE_PORTS else "MEDIUM"


def detect_asset_service_changes(before, after):
    """Compare two state snapshots and return a flat list of structured
    change objects including IP_CHANGED and DEVICE_RETURNED."""
    changes = []
    before_assets = before.get("assets", {})
    after_assets = after.get("assets", {})
    before_services = before.get("services", {})
    after_services = after.get("services", {})

    def _label(asset_id, assets_map):
        a = assets_map.get(asset_id, {})
        ip_txt = a.get("ip") or ""
        host_txt = a.get("hostname") or ""
        if host_txt and ip_txt:
            return f"{host_txt} ({ip_txt})"
        return ip_txt or host_txt or f"Asset #{asset_id}"

    for asset_id, a in after_assets.items():
        if asset_id not in before_assets:
            changes.append({
                "type": "NEW_ASSET", "asset": _label(asset_id, after_assets),
                "hostname": a.get("hostname"), "ip": a.get("ip"), "mac": a.get("mac"),
                "severity": "MEDIUM",
            })
        else:
            prev = before_assets[asset_id]
            # Check IP Change
            if prev.get("ip") and a.get("ip") and prev.get("ip") != a.get("ip"):
                changes.append({
                    "type": "IP_CHANGED",
                    "asset": _label(asset_id, after_assets),
                    "hostname": a.get("hostname"),
                    "old_value": prev.get("ip"),
                    "new_value": a.get("ip"),
                    "mac": a.get("mac"),
                    "severity": "INFO",
                })
            # Check Return from Offline
            if prev.get("status") == "OFFLINE" and a.get("status") == "ONLINE":
                changes.append({
                    "type": "DEVICE_RETURNED",
                    "asset": _label(asset_id, after_assets),
                    "hostname": a.get("hostname"),
                    "ip": a.get("ip"),
                    "mac": a.get("mac"),
                    "severity": "INFO",
                })

    for asset_id, a in before_assets.items():
        was_online = a.get("status") == "ONLINE"
        now = after_assets.get(asset_id)
        if was_online and now and now.get("status") == "OFFLINE":
            changes.append({
                "type": "REMOVED_ASSET", "asset": _label(asset_id, before_assets),
                "hostname": a.get("hostname"), "ip": a.get("ip"), "severity": "LOW",
            })
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
