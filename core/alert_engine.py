"""
ACDS v3.0 — SPRINT 2 — PHASE 7: REAL-TIME ALERT ENGINE
core/alert_engine.py
─────────────────────────────────────────────────────────────────
Pure comparison logic — no Streamlit, no SQLite. Takes a BEFORE and
AFTER snapshot of the asset population (built by app.py from the live
graph) and returns a flat list of structured alert dicts:

    {"timestamp":.., "severity":.., "alert_type":.., "asset":..,
     "title":.., "description":.., "old_value":.., "new_value":..}

alert_type is always one of ALERT_TYPES; severity is always one of
SEVERITIES. This module never talks to the network and never decides
whether to persist/display an alert — app.py does that with
core/database.create_alerts() and the "🚨 REAL-TIME ALERTS" panel.
"""

ALERT_TYPES = {
    "NEW_CVE", "RISK_INCREASE", "CRITICAL_ASSET_EXPOSED",
    "NEW_EXPOSURE_PATH", "HONEYPOT_PATH", "RISK_DECREASE",
    "IP_CHANGED", "DEVICE_RETURNED", "NEW_ASSET", "REMOVED_ASSET",
}

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Minimum |risk delta| before a RISK_INCREASE/RISK_DECREASE alert fires,
# so trivial 0.1-point rounding noise between passes doesn't spam alerts.
_RISK_DELTA_THRESHOLD = 5.0


def _severity_for_risk_delta(delta):
    d = abs(delta)
    if d >= 30:
        return "CRITICAL"
    if d >= 15:
        return "HIGH"
    if d >= 5:
        return "MEDIUM"
    return "LOW"


def _severity_for_cvss(cvss):
    if cvss is None:
        return "MEDIUM"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def _asset_label(after, before, ip):
    a = after or before or {}
    hostname = a.get("hostname")
    return f"{ip} ({hostname})" if hostname else ip


def generate_change_alerts(before_assets, after_assets, before_edges, after_edges,
                            honeypot_triggered, now_iso):
    """
    before_assets / after_assets: dict keyed by asset IP ->
        {
          'hostname':.., 'risk_score':.., 'risk_severity':.., 'criticality':..,
          'cve_ids': set[str], 'cve_cvss': {cve_id: float}, 'exposed': bool,
        }
    before_edges / after_edges: set of (src_ip, dst_ip) modeled
        POTENTIAL REACHABILITY pairs from the exposure graph.
    honeypot_triggered: bool — did the most recent simulation pass hit
        the decoy node.
    now_iso: ISO-8601 timestamp string shared by every alert in this pass,
        so a single recalculation pass reads as one coherent event.

    Returns a list of alert dicts (see module docstring), newest logic
    first but no particular external ordering guarantee.
    """
    alerts = []
    before_assets = before_assets or {}
    after_assets = after_assets or {}
    before_edges = before_edges or set()
    after_edges = after_edges or set()

    # ---- IP_CHANGED ---------------------------------------------------
    from core.change_detector import diff_scans
    diff = diff_scans(before_assets, after_assets)
    for change in diff.get("ip_changed_assets", []):
        old_ip = change.get("old_ip")
        new_ip = change.get("new_ip")
        after_obj = after_assets.get(new_ip, {})
        label = _asset_label(after_obj, None, new_ip)
        alerts.append({
            "timestamp": now_iso, "severity": "INFO",
            "alert_type": "IP_CHANGED", "asset": label,
            "title": "Device IP changed (DHCP reassignment)",
            "description": f"Stable asset {label} migrated from IP {old_ip} to {new_ip}. Historical risk and CVE profile preserved.",
            "old_value": old_ip, "new_value": new_ip,
        })

    # ---- RISK_INCREASE / RISK_DECREASE -------------------------------
    for ip, after in after_assets.items():
        before = before_assets.get(ip)
        if not before:
            continue  # NEW_ASSET is already covered by change_detector; not a risk delta
        before_score = before.get("risk_score")
        after_score = after.get("risk_score")
        if before_score is None or after_score is None:
            continue
        delta = round(after_score - before_score, 1)
        label = _asset_label(after, before, ip)
        if delta >= _RISK_DELTA_THRESHOLD:
            alerts.append({
                "timestamp": now_iso, "severity": _severity_for_risk_delta(delta),
                "alert_type": "RISK_INCREASE", "asset": label,
                "title": "Risk increased",
                "description": f"Asset risk rose from {before_score} to {after_score} "
                                f"({after.get('risk_severity','?')}).",
                "old_value": str(before_score), "new_value": str(after_score),
            })
        elif delta <= -_RISK_DELTA_THRESHOLD:
            alerts.append({
                "timestamp": now_iso, "severity": "INFO",
                "alert_type": "RISK_DECREASE", "asset": label,
                "title": "Risk decreased",
                "description": f"Asset risk fell from {before_score} to {after_score} "
                                f"({after.get('risk_severity','?')}).",
                "old_value": str(before_score), "new_value": str(after_score),
            })

    # ---- NEW_CVE ------------------------------------------------------
    for ip, after in after_assets.items():
        before = before_assets.get(ip, {})
        before_cves = set(before.get("cve_ids") or [])
        after_cves = set(after.get("cve_ids") or [])
        new_cves = after_cves - before_cves
        label = _asset_label(after, before, ip)
        for cve in sorted(new_cves):
            cvss = (after.get("cve_cvss") or {}).get(cve)
            alerts.append({
                "timestamp": now_iso, "severity": _severity_for_cvss(cvss),
                "alert_type": "NEW_CVE", "asset": label,
                "title": f"New vulnerability: {cve}",
                "description": f"{cve} (CVSS {cvss if cvss is not None else 'n/a'}) newly "
                                f"detected on {label}.",
                "old_value": None, "new_value": cve,
            })

    # ---- CRITICAL_ASSET_EXPOSED ----------------------------------------
    for ip, after in after_assets.items():
        if (after.get("criticality") or 0) < 4:
            continue
        before = before_assets.get(ip)
        was_exposed = bool(before and before.get("exposed"))
        is_exposed = bool(after.get("exposed"))
        if is_exposed and not was_exposed:
            label = _asset_label(after, before, ip)
            alerts.append({
                "timestamp": now_iso, "severity": "CRITICAL",
                "alert_type": "CRITICAL_ASSET_EXPOSED", "asset": label,
                "title": "Critical asset newly exposed",
                "description": f"{label} is a CRITICAL/HIGH-criticality asset and is now "
                                f"reachable or exposing open services (was not previously).",
                "old_value": "not exposed", "new_value": "exposed",
            })

    # ---- NEW_EXPOSURE_PATH ---------------------------------------------
    if before_edges:
        new_edges = after_edges - before_edges
        for src, dst in sorted(new_edges):
            after_dst = after_assets.get(dst, {})
            label = _asset_label(after_dst, None, dst)
            alerts.append({
                "timestamp": now_iso, "severity": "MEDIUM",
                "alert_type": "NEW_EXPOSURE_PATH", "asset": label,
                "title": "New exposure path",
                "description": f"New modeled reachability path: {src} → {dst}.",
                "old_value": None, "new_value": f"{src} -> {dst}",
            })

    # ---- HONEYPOT_PATH ----------------------------------------------------
    if honeypot_triggered:
        alerts.append({
            "timestamp": now_iso, "severity": "CRITICAL",
            "alert_type": "HONEYPOT_PATH", "asset": "Honeypot (decoy)",
            "title": "Honeypot path reached",
            "description": "The simulated attacker reached the honeypot decoy during the "
                            "most recent simulation pass.",
            "old_value": None, "new_value": "triggered",
        })

    return alerts


def build_cve_lifecycle_events(before_assets, after_assets, now_iso):
    """Phase 9: derive CVE lifecycle events (DISCOVERED / RESOLVED /
    CVSS_CHANGED) from the same before/after asset snapshots used for
    alerts. Kept separate from generate_change_alerts() because the
    Vulnerability Timeline tracks the full lifecycle (including
    resolutions), not just the alert-worthy subset."""
    events = []
    before_assets = before_assets or {}
    after_assets = after_assets or {}

    all_ips = set(before_assets) | set(after_assets)
    for ip in sorted(all_ips):
        before = before_assets.get(ip, {})
        after = after_assets.get(ip, {})
        before_cves = set(before.get("cve_ids") or [])
        after_cves = set(after.get("cve_ids") or [])
        before_cvss = before.get("cve_cvss") or {}
        after_cvss = after.get("cve_cvss") or {}

        for cve in sorted(after_cves - before_cves):
            events.append({
                "timestamp": now_iso, "asset_ip": ip, "cve_id": cve,
                "event_type": "DISCOVERED", "cvss": after_cvss.get(cve),
                "detail": f"{cve} discovered on {ip}",
            })
        for cve in sorted(before_cves - after_cves):
            events.append({
                "timestamp": now_iso, "asset_ip": ip, "cve_id": cve,
                "event_type": "RESOLVED", "cvss": before_cvss.get(cve),
                "detail": f"{cve} no longer detected on {ip} (patched/upgraded)",
            })
        for cve in sorted(after_cves & before_cves):
            b, a = before_cvss.get(cve), after_cvss.get(cve)
            if b is not None and a is not None and abs(b - a) >= 0.1:
                events.append({
                    "timestamp": now_iso, "asset_ip": ip, "cve_id": cve,
                    "event_type": "CVSS_CHANGED", "cvss": a,
                    "detail": f"{cve} CVSS changed {b} → {a} on {ip}",
                })
    return events
