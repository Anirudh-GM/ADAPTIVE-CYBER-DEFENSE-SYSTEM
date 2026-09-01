"""
ACDS Core Domain Data Models
Provides typed data structures for Assets, Services, Vulnerabilities, Attack Steps,
Honeypot Telemetry, Risk Profiles, and Defense Actions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any


@dataclass
class VulnerabilityFinding:
    """Represents a matched CVE or baseline exposure finding."""
    cve_id: str
    cvss: float
    severity: str
    service: str
    port: int
    detected_product: Optional[str] = None
    detected_version: Optional[str] = None
    summary: str = ""
    published: str = "Unknown"
    modified: str = "Unknown"
    source: str = "nvd_live"  # 'nvd_live', 'offline_table', or 'none'
    detection_confidence: str = "High"


@dataclass
class ServiceInfo:
    """Represents an open network port and associated service metadata."""
    port: int
    name: str
    version: Optional[str] = None
    raw_banner: Optional[str] = None
    is_sensitive: bool = False
    baseline_risk: float = 0.30


@dataclass
class RiskComponentBreakdown:
    """Individual component score and contribution in the 5-component Asset Risk Model."""
    raw_value: float
    normalized_score: float
    weight: float
    contribution: float


@dataclass
class AssetRiskProfile:
    """Full 5-component Asset Risk evaluation."""
    score: float
    severity: str
    components: Dict[str, Dict[str, float]]
    vulnerability_component: float
    service_component: float
    sensitive_component: float
    criticality_component: float
    network_component: float
    sensitive_detected: List[Tuple[int, str]] = field(default_factory=list)


@dataclass
class Asset:
    """Represents a network host/system within the ACDS model."""
    id: str
    ip: str
    hostname: str
    display_name: str
    role: str
    node_type: str = "endpoint"  # 'endpoint', 'server', 'database', 'honeypot', 'perimeter'
    os: str = "unknown"
    os_confidence: Optional[float] = None
    os_evidence: List[str] = field(default_factory=list)
    device_type: str = "Unknown"
    device_confidence: Optional[float] = None
    device_evidence: List[str] = field(default_factory=list)
    mac: Optional[str] = None
    mac_vendor: Optional[str] = None
    is_mobile: bool = False
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    version_map: Dict[str, str] = field(default_factory=dict)
    banner_map: Dict[str, str] = field(default_factory=dict)
    criticality: int = 2  # 1 to 5 stars
    criticality_label: str = "LOW"
    criticality_confidence: Optional[float] = None
    criticality_evidence: List[str] = field(default_factory=list)
    vulnerability: float = 0.0  # 0.0 - 1.0 (score / 100)
    risk_score: float = 0.0  # 0 - 100
    risk_severity: str = "LOW"
    risk_components: Dict[str, Dict[str, float]] = field(default_factory=dict)
    cve_findings: List[Dict[str, Any]] = field(default_factory=list)
    exposure_findings: List[Dict[str, Any]] = field(default_factory=list)
    fixes: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    access_vectors: List[str] = field(default_factory=list)
    cve_source: str = "none"
    compromised: bool = False
    priv_escalated: bool = False
    isolated: bool = False


@dataclass
class AttackStep:
    """Represents a single step in a simulated attack progression."""
    timestep: int
    node: str
    from_node: Optional[str]
    mitre_code: str
    mitre_desc: str
    access_vector: str
    success: bool
    vuln: float
    criticality: int
    ntype: str
    priv_esc: bool = False


@dataclass
class HoneypotObservation:
    """Detailed telemetry recorded when an attacker interacts with a honeypot decoy."""
    timestamp: str
    source_node: str
    honeypot_node: str
    probed_port: int
    service: str
    mitre_code: str
    attempt_count: int
    movement_direction: str
    threat_level: str


@dataclass
class BlastRadiusDetails:
    """Detailed quantitative results from an attack simulation."""
    spread: float
    critical_impact: float
    depth: float
    compromised_count: int
    total_real_nodes: int
    systems_controlled: int
    max_lateral_hops: int
    privilege_escalations: int
    critical_assets_reached: int
    attack_paths: List[List[str]] = field(default_factory=list)


@dataclass
class DefenseAction:
    """Represents a candidate or selected defense recommendation."""
    action: str
    node: str
    type: str  # 'patch', 'isolate', 'privilege', 'ids', 'isolate_vlan'
    cost: int
    risk_reduction: float
    efficiency: float
    description: str
    state: str = "RECOMMENDED"  # 'RECOMMENDED', 'SELECTED', 'APPLIED TO SIMULATION MODEL'


@dataclass
class SimulationResult:
    """Encapsulates the complete outcome of an attack simulation run."""
    timeline: List[Dict[str, Any]]
    compromised_nodes: Set[str]
    honeypot_triggered: bool
    attack_stats: Dict[str, Any]
    risk_score: float
    blast_details: Dict[str, Any]
    overall_risk: Dict[str, Any]
    honeypot_observations: List[Dict[str, Any]] = field(default_factory=list)
    seed: Optional[int] = None


@dataclass
class ComparisonResult:
    """Before vs After comparison between pre-defense and post-defense simulations."""
    risk_before: float
    risk_after: float
    risk_reduction_pct: float
    systems_compromised_before: int
    systems_compromised_after: int
    critical_reached_before: int
    critical_reached_after: int
    max_depth_before: int
    max_depth_after: int
    budget_used: int
    applied_actions: List[DefenseAction]
