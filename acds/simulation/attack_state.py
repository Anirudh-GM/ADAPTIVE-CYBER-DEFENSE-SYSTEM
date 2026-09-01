"""
ACDS Attack State Container
Tracks in-progress attack simulation state, compromised nodes, and step-by-step progress.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any


@dataclass
class AttackProgressState:
    """State of an in-progress attack simulation."""
    timestep: int = 1
    compromised: Set[str] = field(default_factory=set)
    priv_escalated: Set[str] = field(default_factory=set)
    visited: Set[str] = field(default_factory=set)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[List[str]] = field(default_factory=list)
    honeypot_triggered: bool = False
    current_node: Optional[str] = None
    is_complete: bool = False
    honeypot_events: List[Dict[str, Any]] = field(default_factory=list)
