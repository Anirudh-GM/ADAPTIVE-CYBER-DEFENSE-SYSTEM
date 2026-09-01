"""
ACDS Authoritative State Management
Encapsulates session state, network graph, simulation metrics, and audit history.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
import networkx as nx

@dataclass
class SystemState:
    """Authoritative state container for the ACDS platform."""
    network_mode: str = "Real Network Scan"
    G: nx.DiGraph = field(default_factory=nx.DiGraph)
    simulation_done: bool = False
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    compromised: Set[str] = field(default_factory=set)
    risk_score: float = 0.0
    blast_details: Dict[str, Any] = field(default_factory=dict)
    honeypot_triggered: bool = False
    defense_actions: List[Dict[str, Any]] = field(default_factory=list)
    selected_defenses: List[Dict[str, Any]] = field(default_factory=list)
    applied_defenses: List[Dict[str, Any]] = field(default_factory=list)
    ids_deployed: bool = False
    segmentation_applied: bool = False
    attack_log: List[Dict[str, Any]] = field(default_factory=list)
    attack_stats: Dict[str, Any] = field(default_factory=dict)
    current_anim_node: Optional[str] = None
    last_scan_devices: Optional[List[Tuple]] = None
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    scan_error: Optional[str] = None
    scan_timeline: List[Dict[str, Any]] = field(default_factory=list)
    scan_history: List[Dict[str, Any]] = field(default_factory=list)
    scan_counter: int = 0
    risk_before_defense: Optional[float] = None
    blast_before_defense: Dict[str, Any] = field(default_factory=dict)
    post_defense_stats: Optional[Dict[str, Any]] = None
    overall_acds_risk: Optional[Dict[str, Any]] = None
    budget: int = 50

    def reset_simulation(self) -> None:
        """Reset simulation state while preserving network topology."""
        for node in self.G.nodes:
            self.G.nodes[node]["compromised"] = False
        self.simulation_done = False
        self.timeline = []
        self.compromised = set()
        self.risk_score = 0.0
        self.blast_details = {}
        self.honeypot_triggered = False
        self.defense_actions = []
        self.selected_defenses = []
        self.attack_log = []
        self.current_anim_node = None
        self.overall_acds_risk = None
