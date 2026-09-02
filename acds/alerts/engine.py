"""
ACDS Real-Time Alert Generation & Notification Engine
Translates network diff mutations, newly exposed sensitive ports, CVE introductions,
risk score surges, and deception telemetry into prioritized security alerts.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any
import uuid

from acds.comparison.diff import ScanComparisonResult, AssetDiff


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class SecurityAlert:
    """Structured security alert entity."""
    alert_id: str
    timestamp: str
    alert_type: str  # NEW_ASSET | REMOVED_ASSET | NEW_PORT | CLOSED_PORT | SERVICE_MUTATION | NEW_CVE | RESOLVED_CVE | RISK_INCREASE | CRITICAL_EXPOSURE | HONEYPOT_TRIGGERED
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str
    asset_ip: str = ""
    asset_name: str = ""
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None
    risk_delta: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    suggested_action: str = ""
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "asset_ip": self.asset_ip,
            "asset_name": self.asset_name,
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
            "risk_delta": self.risk_delta,
            "details": self.details,
            "suggested_action": self.suggested_action,
            "acknowledged": self.acknowledged,
        }


class AlertEngine:
    """
    Central Alert Evaluation and Dispatch Engine.
    Evaluates scan diffs and produces actionable security alerts.
    """

    def __init__(self, risk_delta_threshold: float = 10.0):
        self.risk_delta_threshold = risk_delta_threshold

    @staticmethod
    def _gen_id() -> str:
        return f"ALT-{uuid.uuid4().hex[:8].upper()}"

    def generate_alerts_from_diff(
        self,
        diff: ScanComparisonResult,
        timestamp: Optional[str] = None,
    ) -> List[SecurityAlert]:
        """
        Evaluate a ScanComparisonResult and generate granular prioritized security alerts.
        """
        now = timestamp or _now_iso()
        alerts: List[SecurityAlert] = []

        # 1. New Devices Joined
        for dev in diff.new_devices:
            ip = dev.get("ip", "")
            host = dev.get("hostname", ip)
            risk = dev.get("risk_score", 0.0)
            ports = dev.get("open_ports", [])
            dev_type = dev.get("device_type", "Unknown")

            sev = "HIGH" if (risk >= 60.0 or 445 in ports or 3389 in ports) else "MEDIUM" if risk >= 40.0 else "INFO"
            act = "Audit new device MAC address and verify network authorization."
            if ports:
                act += f" Review exposed ports ({ports})."

            alerts.append(SecurityAlert(
                alert_id=self._gen_id(),
                timestamp=now,
                alert_type="NEW_ASSET",
                severity=sev,
                title=f"New Asset Discovered: {host} ({ip})",
                description=f"New {dev_type} joined the subnet with {len(ports)} open port(s) and initial risk score {risk:.1f}.",
                asset_ip=ip,
                asset_name=host,
                risk_after=risk,
                details={"open_ports": ports, "device_type": dev_type},
                suggested_action=act,
            ))

        # 2. Removed Devices
        for dev in diff.removed_devices:
            ip = dev.get("ip", "")
            host = dev.get("hostname", ip)
            alerts.append(SecurityAlert(
                alert_id=self._gen_id(),
                timestamp=now,
                alert_type="REMOVED_ASSET",
                severity="INFO",
                title=f"Asset Offline: {host} ({ip})",
                description=f"Monitored host {host} dropped off the network or stopped responding to probes.",
                asset_ip=ip,
                asset_name=host,
                suggested_action="Verify if device was decommissioned or experiencing network outage.",
            ))

        # 3. Modified Devices & Port Mutations
        for mod in diff.modified_devices:
            ip = mod.ip
            host = mod.hostname or ip

            for det in mod.details:
                if "Port(s) opened:" in det:
                    is_sensitive = any(p in det for p in ["445", "3389", "3306", "5432", "21", "23"])
                    sev = "CRITICAL" if is_sensitive else "HIGH"
                    alerts.append(SecurityAlert(
                        alert_id=self._gen_id(),
                        timestamp=now,
                        alert_type="NEW_PORT",
                        severity=sev,
                        title=f"New Port(s) Opened on {host}",
                        description=f"Port mutation detected on {host} ({ip}): {det}",
                        asset_ip=ip,
                        asset_name=host,
                        risk_before=mod.risk_before,
                        risk_after=mod.risk_after,
                        risk_delta=mod.risk_delta,
                        details={"detail_string": det},
                        suggested_action="Inspect service listener and enforce host firewall rules." if not is_sensitive else "IMMEDIATE: Restrict sensitive administrative port access.",
                    ))
                elif "Port(s) closed:" in det:
                    alerts.append(SecurityAlert(
                        alert_id=self._gen_id(),
                        timestamp=now,
                        alert_type="CLOSED_PORT",
                        severity="INFO",
                        title=f"Port(s) Closed on {host}",
                        description=f"Services ceased listening on {host} ({ip}): {det}",
                        asset_ip=ip,
                        asset_name=host,
                        details={"detail_string": det},
                        suggested_action="Confirm expected maintenance or port hardening.",
                    ))
                elif "Version changed" in det:
                    alerts.append(SecurityAlert(
                        alert_id=self._gen_id(),
                        timestamp=now,
                        alert_type="SERVICE_MUTATION",
                        severity="MEDIUM",
                        title=f"Service Version Modified on {host}",
                        description=f"Software version transition detected on {host} ({ip}): {det}",
                        asset_ip=ip,
                        asset_name=host,
                        details={"detail_string": det},
                        suggested_action="Verify authorized upgrade and re-evaluate vulnerability profile.",
                    ))

            # Risk Surge Alert
            if mod.risk_delta is not None and mod.risk_delta >= self.risk_delta_threshold:
                alerts.append(SecurityAlert(
                    alert_id=self._gen_id(),
                    timestamp=now,
                    alert_type="RISK_INCREASE",
                    severity="HIGH" if mod.risk_delta < 25.0 else "CRITICAL",
                    title=f"Risk Score Surge on {host} (+{mod.risk_delta:.1f} pts)",
                    description=f"Operational risk shifted from {mod.risk_before:.1f} to {mod.risk_after:.1f} on {host} ({ip}).",
                    asset_ip=ip,
                    asset_name=host,
                    risk_before=mod.risk_before,
                    risk_after=mod.risk_after,
                    risk_delta=mod.risk_delta,
                    suggested_action="Review top prioritized remediation actions to counteract risk escalation.",
                ))

        # 4. New Vulnerabilities
        for cve_item in diff.new_vulnerabilities:
            ip = cve_item.get("ip", "")
            cve_id = cve_item.get("cve_id", "")
            alerts.append(SecurityAlert(
                alert_id=self._gen_id(),
                timestamp=now,
                alert_type="NEW_CVE",
                severity="HIGH",
                title=f"New Vulnerability {cve_id} on {ip}",
                description=f"Security intelligence correlated new finding {cve_id} against active services on {ip}.",
                asset_ip=ip,
                asset_name=ip,
                details={"cve_id": cve_id},
                suggested_action=f"Apply vendor security patch for {cve_id}.",
            ))

        # 5. Resolved Vulnerabilities
        for cve_item in diff.resolved_vulnerabilities:
            ip = cve_item.get("ip", "")
            cve_id = cve_item.get("cve_id", "")
            alerts.append(SecurityAlert(
                alert_id=self._gen_id(),
                timestamp=now,
                alert_type="RESOLVED_CVE",
                severity="INFO",
                title=f"Vulnerability Remediated: {cve_id} on {ip}",
                description=f"Finding {cve_id} is no longer detected on {ip} (remediation verified).",
                asset_ip=ip,
                asset_name=ip,
                details={"cve_id": cve_id},
                suggested_action="Mark finding as resolved in compliance tracking.",
            ))

        # Sort alerts by severity rank: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        alerts.sort(key=lambda a: (rank.get(a.severity, 5), a.timestamp))
        return alerts

    def generate_honeypot_alert(
        self,
        adversary_entry: str,
        honeypot_node: str,
        targeted_services: List[str],
        timestamp: Optional[str] = None,
    ) -> SecurityAlert:
        """Generate high-priority deception telemetry alert when a decoy node is probed."""
        now = timestamp or _now_iso()
        return SecurityAlert(
            alert_id=self._gen_id(),
            timestamp=now,
            alert_type="HONEYPOT_TRIGGERED",
            severity="CRITICAL",
            title=f"DECEPTION TRAP TRIGGERED: {honeypot_node}",
            description=(
                f"Adversary traversal from entry '{adversary_entry}' touched decoy node '{honeypot_node}'. "
                f"Targeted protocols: {', '.join(targeted_services) if targeted_services else 'All Ports'}."
            ),
            asset_ip=honeypot_node,
            asset_name=honeypot_node,
            details={"entry_point": adversary_entry, "honeypot": honeypot_node, "targeted_services": targeted_services},
            suggested_action="Isolate entry point host immediately and deploy dynamic defense multiplier.",
        )
