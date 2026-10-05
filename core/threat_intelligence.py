"""
ACDS v4.0 — PHASE 10: Threat Intelligence

Integrates:
  - NVD (already integrated in app.py — extended here)
  - MITRE ATT&CK (technique validation from attack_graph_intelligence.py)
  - CISA KEV (Known Exploited Vulnerabilities catalog)
  - Vendor advisories (heuristic enrichment)

Threat intelligence INFLUENCES prioritization, not just display.
Known Exploited Vulnerabilities (CISA KEV) increase priority ONLY
when exposure conditions are satisfied (asset is reachable + port is open).

All external data is cached. Offline fallback is always available.
"""

from __future__ import annotations
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from core.acds_logging import get_logger

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────
# CISA KEV — Known Exploited Vulnerabilities
# Offline representative subset (real KEV catalog updated weekly at
# https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
# These are real CISA KEV entries as of mid-2025.
# ─────────────────────────────────────────────────────────────────
CISA_KEV_OFFLINE: Dict[str, Dict[str, Any]] = {
    "CVE-2019-0708": {
        "cve_id": "CVE-2019-0708",
        "vendor": "Microsoft",
        "product": "Windows (RDP)",
        "name": "BlueKeep",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "notes": "Actively exploited in ransomware campaigns.",
        "kev_priority_boost": 25,
    },
    "CVE-2017-7494": {
        "cve_id": "CVE-2017-7494",
        "vendor": "Samba",
        "product": "Samba",
        "name": "SambaCry",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "notes": "Remote code execution via SMB share library upload.",
        "kev_priority_boost": 22,
    },
    "CVE-2021-41773": {
        "cve_id": "CVE-2021-41773",
        "vendor": "Apache",
        "product": "Apache HTTP Server 2.4.49",
        "name": "Apache Path Traversal",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "notes": "Path traversal and RCE via mod_cgi.",
        "kev_priority_boost": 20,
    },
    "CVE-2021-42013": {
        "cve_id": "CVE-2021-42013",
        "vendor": "Apache",
        "product": "Apache HTTP Server 2.4.50",
        "name": "Apache RCE (follow-on)",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "notes": "Incomplete fix for CVE-2021-41773.",
        "kev_priority_boost": 22,
    },
    "CVE-2017-7269": {
        "cve_id": "CVE-2017-7269",
        "vendor": "Microsoft",
        "product": "IIS 6.0",
        "name": "IIS WebDAV Buffer Overflow",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "notes": "Buffer overflow in WebDAV ScStoragePathFromUrl.",
        "kev_priority_boost": 20,
    },
    "CVE-2015-3306": {
        "cve_id": "CVE-2015-3306",
        "vendor": "ProFTPD",
        "product": "ProFTPD 1.3.5",
        "name": "ProFTPD mod_copy RCE",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "notes": "Unauthenticated file read/write via mod_copy.",
        "kev_priority_boost": 20,
    },
    "CVE-2011-2523": {
        "cve_id": "CVE-2011-2523",
        "vendor": "vsftpd",
        "product": "vsftpd 2.3.4",
        "name": "vsftpd Backdoor",
        "date_added": "2021-11-03",
        "due_date": "2021-11-17",
        "notes": "Backdoor command execution in vsftpd 2.3.4.",
        "kev_priority_boost": 25,
    },
    "CVE-2023-44487": {
        "cve_id": "CVE-2023-44487",
        "vendor": "Various",
        "product": "HTTP/2 servers",
        "name": "HTTP/2 Rapid Reset Attack",
        "date_added": "2023-10-10",
        "due_date": "2023-10-31",
        "notes": "HTTP/2 rapid reset DDoS vulnerability.",
        "kev_priority_boost": 15,
    },
    "CVE-2024-3400": {
        "cve_id": "CVE-2024-3400",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "name": "PAN-OS Command Injection",
        "date_added": "2024-04-12",
        "due_date": "2024-04-19",
        "notes": "Command injection in GlobalProtect gateway.",
        "kev_priority_boost": 25,
    },
    "CVE-2024-21762": {
        "cve_id": "CVE-2024-21762",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "name": "FortiOS OOB Write",
        "date_added": "2024-02-09",
        "due_date": "2024-02-16",
        "notes": "Out-of-bounds write in SSL-VPN.",
        "kev_priority_boost": 22,
    },
}


def is_in_cisa_kev(cve_id: str) -> Optional[Dict[str, Any]]:
    """Check if a CVE ID is in the CISA KEV catalog (offline subset)."""
    return CISA_KEV_OFFLINE.get(cve_id)


def enrich_cve_with_threat_intel(
    cve_findings: List[Dict[str, Any]],
    asset_is_exposed: bool = True,
    asset_is_reachable: bool = True,
) -> List[Dict[str, Any]]:
    """
    Phase 10: Enrich CVE findings with threat intelligence.
    CISA KEV priority boost is ONLY applied when:
     - asset_is_exposed: asset has at least one open port
     - asset_is_reachable: asset is network-reachable (in-degree > 0)
    """
    enriched = []
    for cve in cve_findings:
        cve_id = cve.get("cve_id", "")
        enriched_cve = dict(cve)

        # CISA KEV check
        kev_entry = is_in_cisa_kev(cve_id)
        if kev_entry:
            enriched_cve["in_cisa_kev"] = True
            enriched_cve["kev_name"] = kev_entry.get("name")
            enriched_cve["kev_date_added"] = kev_entry.get("date_added")
            enriched_cve["kev_notes"] = kev_entry.get("notes")

            # Priority boost only when exposure conditions are met
            if asset_is_exposed and asset_is_reachable:
                boost = kev_entry.get("kev_priority_boost", 10)
                enriched_cve["kev_priority_boost"] = boost
                enriched_cve["kev_boost_applied"] = True
                enriched_cve["kev_boost_reason"] = (
                    f"CISA KEV confirmed + asset is exposed and reachable → priority boosted by {boost}pts"
                )
            else:
                enriched_cve["kev_priority_boost"] = 0
                enriched_cve["kev_boost_applied"] = False
                enriched_cve["kev_boost_reason"] = (
                    f"CISA KEV confirmed but exposure conditions NOT satisfied "
                    f"(exposed={asset_is_exposed}, reachable={asset_is_reachable}) → no boost"
                )
        else:
            enriched_cve["in_cisa_kev"] = False
            enriched_cve["kev_priority_boost"] = 0
            enriched_cve["kev_boost_applied"] = False

        enriched.append(enriched_cve)

    # Sort: KEV first, then by CVSS descending
    enriched.sort(key=lambda c: (c.get("in_cisa_kev", False), c.get("cvss", 0) or 0), reverse=True)
    return enriched


def calculate_ti_adjusted_priority(
    base_priority: float,
    cve_findings: List[Dict[str, Any]],
) -> Tuple[float, str]:
    """
    Apply threat intelligence boosts to a base priority score.
    Returns (adjusted_priority, explanation).
    """
    total_boost = sum(
        c.get("kev_priority_boost", 0)
        for c in cve_findings
        if c.get("kev_boost_applied")
    )
    adjusted = min(100.0, base_priority + total_boost)
    kev_ids = [c.get("cve_id") for c in cve_findings if c.get("kev_boost_applied")]
    explanation = (
        f"Base priority {base_priority:.0f} + CISA KEV boost +{total_boost}pts "
        f"({', '.join(kev_ids)}) = {adjusted:.0f}"
        if kev_ids else
        f"Base priority {base_priority:.0f} (no CISA KEV adjustment)"
    )
    return round(adjusted, 1), explanation


def get_vendor_advisory_hints(service: str, version: Optional[str]) -> Optional[str]:
    """
    Heuristic vendor advisory hints for common services.
    Returns a short advisory note or None.
    """
    if not service:
        return None
    s = service.lower()
    v = (version or "").lower()

    advisories = {
        ("ssh", "7.2"): "OpenSSH 7.x series reached EOL — upgrade to 8.x+ for improved security.",
        ("ssh", "6."): "OpenSSH 6.x is severely out of date — multiple known CVEs, upgrade immediately.",
        ("apache", "2.4.49"): "Apache 2.4.49 has active CISA KEV (CVE-2021-41773) — patch to 2.4.51+.",
        ("apache", "2.4.50"): "Apache 2.4.50 has active CISA KEV (CVE-2021-42013) — patch to 2.4.51+.",
        ("mysql", "5.5"): "MySQL 5.5 is end-of-life — upgrade to 8.0+.",
        ("rdp", ""): "RDP should never be directly internet-facing — require VPN + NLA + MFA.",
        ("ftp", ""): "FTP transmits credentials in plaintext — migrate to SFTP or FTPS.",
        ("telnet", ""): "Telnet is plaintext and should be disabled immediately — use SSH.",
    }

    for (svc_hint, ver_hint), advisory in advisories.items():
        if svc_hint in s and (not ver_hint or ver_hint in v):
            return advisory

    return None


def render_threat_intel_badge(cve: Dict[str, Any]) -> str:
    """Render a CISA KEV or threat intel badge for a CVE."""
    if not cve.get("in_cisa_kev"):
        return ""
    boost_applied = cve.get("kev_boost_applied", False)
    boost_color = "#ff3355" if boost_applied else "#ffd700"
    boost_text = f"+{cve.get('kev_priority_boost', 0)}pts priority" if boost_applied else "boost not applied (not exposed)"
    return (
        f"<span style='background:rgba(255,51,85,0.15);border:1px solid {boost_color};"
        f"color:{boost_color};font-family:Share Tech Mono;font-size:0.6rem;"
        f"padding:2px 6px;margin:2px;border-radius:3px'>"
        f"⚠ CISA KEV: {cve.get('kev_name', cve.get('cve_id', ''))} — {boost_text}"
        f"</span>"
    )
