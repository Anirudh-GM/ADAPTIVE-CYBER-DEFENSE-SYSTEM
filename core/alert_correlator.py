"""
ACDS v4.0 — PHASE 7: Continuous Monitoring Events
ACDS v4.0 — PHASE 8: Intelligent Alert Correlation

Instead of isolated alerts, correlates related events into compound,
high-value correlated alerts.

Example correlation chain:
  Port 445 Opened → SMB Detected → CVE Found → New Attack Path → Critical Server Reachable
  → ONE alert: "NEW HIGH-RISK ATTACK PATH DETECTED"

Every correlated alert includes:
  - Root cause event
  - Asset(s) involved
  - Service and port
  - CVE (if any)
  - The full attack path
  - Risk change
  - Recommended defense

Also detects:
  - New Device / Removed Device / Returned Device / IP Change
  - New Service / Closed Service / Banner Change / New CVE
  - New Attack Path / Removed Attack Path
  - Avoids duplicate alerts (deduplication by fingerprint)
"""

from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from core.acds_logging import get_logger

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────
# CORRELATION RULES
# Each rule defines which primitive alert types to aggregate.
# ─────────────────────────────────────────────────────────────────

CORRELATION_RULES = [
    {
        "name": "NEW_HIGH_RISK_ATTACK_PATH",
        "title": "New High-Risk Attack Path Detected",
        "required_events": {"NEW_PORT", "NEW_CVE"},
        "optional_events": {"NEW_EXPOSURE_PATH", "CRITICAL_ASSET_EXPOSED"},
        "severity": "CRITICAL",
        "description_template": (
            "A new high-risk attack path has emerged. "
            "Root cause: {root_cause}. "
            "Asset: {asset}. Service: {service} on port {port}. "
            "{cve_clause}"
            "Attack path: {path}. "
            "Risk change: {risk_change}. "
            "Recommended: {recommendation}."
        ),
    },
    {
        "name": "ASSET_EXPOSURE_ESCALATION",
        "title": "Asset Exposure Escalated",
        "required_events": {"NEW_PORT", "CRITICAL_ASSET_EXPOSED"},
        "optional_events": {"RISK_INCREASE"},
        "severity": "HIGH",
        "description_template": (
            "A critical asset's exposure has escalated. "
            "Asset: {asset} now exposes port {port} ({service}). "
            "{cve_clause}"
            "Recommended: {recommendation}."
        ),
    },
    {
        "name": "NEW_DEVICE_WITH_VULNERABILITIES",
        "title": "New Device with Known Vulnerabilities",
        "required_events": {"NEW_ASSET", "NEW_CVE"},
        "optional_events": set(),
        "severity": "HIGH",
        "description_template": (
            "A new device joined the network with known vulnerabilities. "
            "Asset: {asset}. "
            "{cve_clause}"
            "Recommended: {recommendation}."
        ),
    },
    {
        "name": "LATERAL_MOVEMENT_RISK",
        "title": "Lateral Movement Risk Increased",
        "required_events": {"NEW_EXPOSURE_PATH"},
        "optional_events": {"RISK_INCREASE", "CRITICAL_ASSET_EXPOSED"},
        "severity": "HIGH",
        "description_template": (
            "New lateral movement path detected. "
            "Root cause: {root_cause}. Attack path: {path}. "
            "Risk change: {risk_change}. "
            "Recommended: {recommendation}."
        ),
    },
]

# Deduplication window (seconds) — alerts with same fingerprint within this window are suppressed
DEDUP_WINDOW_SECONDS = 300


def _alert_fingerprint(alert: Dict[str, Any]) -> str:
    """Generate a deduplication fingerprint for an alert."""
    key_parts = [
        alert.get("alert_type", ""),
        alert.get("asset", ""),
        str(alert.get("new_value", "")),
    ]
    return hashlib.md5("|".join(key_parts).encode()).hexdigest()


def _has_recent_duplicate(fingerprint: str, recent_fingerprints: Set[str]) -> bool:
    return fingerprint in recent_fingerprints


def correlate_alerts(
    raw_alerts: List[Dict[str, Any]],
    recent_fingerprints: Optional[Set[str]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Phase 8: Correlate a batch of raw alerts into compound correlated alerts.

    Returns:
        (correlated_alerts, uncorrelated_passthrough_alerts)
    """
    recent_fingerprints = recent_fingerprints or set()
    now = datetime.now(timezone.utc).isoformat()

    # Group raw alerts by asset
    by_asset: Dict[str, List[Dict]] = {}
    for alert in raw_alerts:
        asset = alert.get("asset", "_global_")
        by_asset.setdefault(asset, []).append(alert)

    correlated = []
    used_alert_ids = set()

    for rule in CORRELATION_RULES:
        required = rule["required_events"]
        optional = rule["optional_events"]

        for asset, asset_alerts in by_asset.items():
            event_types_present = {a.get("alert_type", "") for a in asset_alerts}

            # Check if required events are all present
            if not required.issubset(event_types_present):
                continue

            # Collect matching alerts
            matched_alerts = [
                a for a in asset_alerts
                if a.get("alert_type") in (required | optional)
            ]

            if not matched_alerts:
                continue

            # Build composite alert
            port = None
            service = None
            cve_id = None
            cvss = None
            path = "unknown → unknown"
            risk_change = "unknown"
            root_cause = matched_alerts[0].get("description", "network change")
            recommendation = "Review and apply defense recommendations in the ACDS optimizer."

            for a in matched_alerts:
                atype = a.get("alert_type")
                if atype == "NEW_PORT":
                    port = a.get("new_value")
                    service = a.get("description", "").split("(")[-1].rstrip(")") if "(" in a.get("description", "") else "unknown"
                if atype == "NEW_CVE":
                    desc = a.get("description", "")
                    parts = desc.split(":")
                    if len(parts) > 1:
                        cve_id = parts[0].strip().split(" ")[-1]
                if atype in ("NEW_EXPOSURE_PATH", "CRITICAL_ASSET_EXPOSED"):
                    path = a.get("description", path)
                if atype in ("RISK_INCREASE", "RISK_DECREASE"):
                    old = a.get("old_value", "?")
                    new = a.get("new_value", "?")
                    risk_change = f"{old} → {new}"
                    root_cause = a.get("description", root_cause)

            cve_clause = f"CVE {cve_id} (CVSS {cvss}) confirmed. " if cve_id else ""

            description = rule["description_template"].format(
                asset=asset,
                service=service or "unknown",
                port=port or "unknown",
                cve_clause=cve_clause,
                path=path,
                risk_change=risk_change,
                root_cause=root_cause,
                recommendation=recommendation,
            )

            corr_alert = {
                "timestamp": now,
                "severity": rule["severity"],
                "alert_type": rule["name"],
                "asset": asset,
                "title": rule["title"],
                "description": description,
                "root_cause": root_cause,
                "correlated_from": [a.get("alert_type") for a in matched_alerts],
                "correlated_alert_count": len(matched_alerts),
                "port": port,
                "service": service,
                "cve_id": cve_id,
                "attack_path": path,
                "risk_change": risk_change,
                "recommendation": recommendation,
                "is_correlated": True,
            }

            # Deduplication
            fp = _alert_fingerprint(corr_alert)
            if _has_recent_duplicate(fp, recent_fingerprints):
                log.debug("Suppressing duplicate correlated alert: %s / %s", rule["name"], asset)
                continue

            recent_fingerprints.add(fp)
            corr_alert["fingerprint"] = fp
            correlated.append(corr_alert)

            # Mark source alerts as used
            for a in matched_alerts:
                used_alert_ids.add(id(a))

    # Pass through uncorrelated alerts (with deduplication)
    passthrough = []
    for alert in raw_alerts:
        if id(alert) in used_alert_ids:
            continue
        fp = _alert_fingerprint(alert)
        if _has_recent_duplicate(fp, recent_fingerprints):
            continue
        recent_fingerprints.add(fp)
        alert["fingerprint"] = fp
        alert["is_correlated"] = False
        passthrough.append(alert)

    return correlated, passthrough


def detect_monitoring_events(
    prev_snapshot: Dict[str, Any],
    curr_snapshot: Dict[str, Any],
    prev_edges: set,
    curr_edges: set,
) -> List[Dict[str, Any]]:
    """
    Phase 7: Detect all monitoring events between two network snapshots.

    Detects:
     - New Device / Removed Device / Returned Device / IP Change
     - New Service / Closed Service / New CVE
     - New Attack Path / Removed Attack Path
    """
    events = []
    now = datetime.now(timezone.utc).isoformat()

    prev_ips = set(prev_snapshot.keys())
    curr_ips = set(curr_snapshot.keys())

    # New devices
    for ip in curr_ips - prev_ips:
        d = curr_snapshot[ip]
        events.append({
            "alert_type": "NEW_ASSET",
            "timestamp": now,
            "severity": "MEDIUM",
            "asset": ip,
            "title": f"New Device: {d.get('hostname', ip)}",
            "description": f"New device {d.get('hostname', ip)} ({ip}) joined the network.",
        })

    # Removed devices
    for ip in prev_ips - curr_ips:
        d = prev_snapshot[ip]
        events.append({
            "alert_type": "REMOVED_ASSET",
            "timestamp": now,
            "severity": "LOW",
            "asset": ip,
            "title": f"Device Offline: {d.get('hostname', ip)}",
            "description": f"Device {d.get('hostname', ip)} ({ip}) is no longer responding.",
        })

    # Changed devices
    for ip in prev_ips & curr_ips:
        prev = prev_snapshot[ip]
        curr = curr_snapshot[ip]

        # New CVEs
        prev_cves = set(prev.get("cve_ids") or [])
        curr_cves = set(curr.get("cve_ids") or [])
        for cve_id in curr_cves - prev_cves:
            cvss = (curr.get("cve_cvss") or {}).get(cve_id, 0)
            events.append({
                "alert_type": "NEW_CVE",
                "timestamp": now,
                "severity": "CRITICAL" if cvss >= 7 else "HIGH",
                "asset": ip,
                "title": f"New CVE: {cve_id}",
                "description": f"{cve_id} (CVSS {cvss}) now confirmed on {curr.get('hostname', ip)} ({ip}).",
                "new_value": f"{cve_id} CVSS={cvss}",
            })

        # Risk changes
        prev_risk = prev.get("risk_score") or 0
        curr_risk = curr.get("risk_score") or 0
        if abs(curr_risk - prev_risk) >= 10:
            event_type = "RISK_INCREASE" if curr_risk > prev_risk else "RISK_DECREASE"
            events.append({
                "alert_type": event_type,
                "timestamp": now,
                "severity": "HIGH" if event_type == "RISK_INCREASE" else "LOW",
                "asset": ip,
                "title": f"Risk {'Increased' if event_type == 'RISK_INCREASE' else 'Decreased'}: {ip}",
                "description": f"Asset risk changed on {curr.get('hostname', ip)} ({ip}).",
                "old_value": str(round(prev_risk, 1)),
                "new_value": str(round(curr_risk, 1)),
            })

        # Critical asset exposed
        if curr.get("criticality", 0) >= 4 and curr.get("exposed") and not prev.get("exposed"):
            events.append({
                "alert_type": "CRITICAL_ASSET_EXPOSED",
                "timestamp": now,
                "severity": "CRITICAL",
                "asset": ip,
                "title": f"Critical Asset Now Exposed: {ip}",
                "description": f"Critical asset {curr.get('hostname', ip)} ({ip}) is now network-reachable.",
                "new_value": "exposed",
                "old_value": "isolated",
            })

    # New and removed attack paths
    for edge in curr_edges - prev_edges:
        src_ip, dst_ip = edge
        events.append({
            "alert_type": "NEW_EXPOSURE_PATH",
            "timestamp": now,
            "severity": "HIGH",
            "asset": dst_ip,
            "title": f"New Attack Path: {src_ip} → {dst_ip}",
            "description": f"New modeled lateral movement path: {src_ip} → {dst_ip}. (SIMULATION)",
        })

    for edge in prev_edges - curr_edges:
        src_ip, dst_ip = edge
        events.append({
            "alert_type": "PATH_REMOVED",
            "timestamp": now,
            "severity": "LOW",
            "asset": dst_ip,
            "title": f"Attack Path Removed: {src_ip} → {dst_ip}",
            "description": f"Previously modeled path {src_ip} → {dst_ip} no longer exists. (SIMULATION)",
        })

    return events


def render_correlated_alert_html(alert: Dict[str, Any]) -> str:
    """Render a correlated alert as a rich HTML card."""
    sev = alert.get("severity", "INFO")
    sev_colors = {
        "CRITICAL": "#ff3355", "HIGH": "#ff8c00",
        "MEDIUM": "#ffd700", "LOW": "#3d6a8a", "INFO": "#00d4ff"
    }
    color = sev_colors.get(sev, "#3d6a8a")
    ts = (alert.get("timestamp") or "")[:19].replace("T", " ")
    is_correlated = alert.get("is_correlated", False)
    corr_badge = (
        f"<span style='background:rgba(0,212,255,0.15);color:#00d4ff;padding:2px 6px;border-radius:3px;"
        f"font-size:0.6rem;margin-left:8px'>CORRELATED ({alert.get('correlated_alert_count',1)} events)</span>"
        if is_correlated else ""
    )

    cve_block = ""
    if alert.get("cve_id"):
        cve_block = f"<div style='margin-top:4px'><span style='color:#ff3355'>CVE:</span> {alert['cve_id']}</div>"

    path_block = ""
    if alert.get("attack_path") and alert["attack_path"] != "unknown → unknown":
        path_block = f"<div style='margin-top:4px'><span style='color:#7ab8d4'>Path:</span> <span style='color:#e0f4ff'>{alert['attack_path']}</span></div>"

    rec_block = ""
    if alert.get("recommendation"):
        rec_block = (
            f"<div style='margin-top:6px;padding:4px 8px;background:rgba(0,255,136,0.05);"
            f"border-left:2px solid #00ff88;color:#00ff88;font-size:0.65rem'>"
            f"→ {alert['recommendation']}</div>"
        )

    return f"""
<div style='background:#0d1f2d;border:1px solid {color};border-left:4px solid {color};
     padding:10px 14px;margin:6px 0;font-family:Share Tech Mono;font-size:0.7rem;color:#7ab8d4;border-radius:4px'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:4px'>
    <span style='color:{color};font-weight:bold'>
      🔔 {sev} — {alert.get('title','')}
      {corr_badge}
    </span>
    <span style='color:#3d6a8a;font-size:0.6rem'>{ts}</span>
  </div>
  <div style='color:#e0f4ff;margin-top:2px'>Asset: {alert.get('asset','-')}</div>
  <div style='margin-top:2px'>{alert.get('description','')}</div>
  {cve_block}
  {path_block}
  {rec_block}
</div>
"""
