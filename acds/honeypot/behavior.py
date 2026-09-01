"""
ACDS Attacker Behavioral Telemetry Engine
Captures attacker profiling data from honeypot interactions (probed ports, origin vectors,
velocity, and targeted service categories).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Any


@dataclass
class AttackerBehaviorProfile:
    """Aggregated behavioral profile of an observed attacker."""
    attacker_origin: str
    targeted_ports: Set[int] = field(default_factory=set)
    targeted_services: Set[str] = field(default_factory=set)
    total_interactions: int = 0
    first_seen_timestep: int = 1
    last_seen_timestep: int = 1
    observed_techniques: Set[str] = field(default_factory=set)
    attack_velocity: float = 0.0  # interactions per timestep

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attacker_origin": self.attacker_origin,
            "targeted_ports": list(self.targeted_ports),
            "targeted_services": list(self.targeted_services),
            "total_interactions": self.total_interactions,
            "first_seen_timestep": self.first_seen_timestep,
            "last_seen_timestep": self.last_seen_timestep,
            "observed_techniques": list(self.observed_techniques),
            "attack_velocity": round(self.attack_velocity, 2),
        }


def extract_attacker_behavior(
    honeypot_events: List[Dict[str, Any]],
) -> Dict[str, AttackerBehaviorProfile]:
    """
    Extract structured behavioral profiles for all attackers observed at honeypots.
    """
    profiles: Dict[str, AttackerBehaviorProfile] = {}

    for event in honeypot_events:
        src = event.get("source", "Unknown-Attacker")
        if src not in profiles:
            profiles[src] = AttackerBehaviorProfile(
                attacker_origin=src,
                first_seen_timestep=event.get("timestep", 1),
            )

        prof = profiles[src]
        prof.total_interactions += 1
        prof.last_seen_timestep = max(prof.last_seen_timestep, event.get("timestep", 1))

        port = event.get("port")
        if port:
            prof.targeted_ports.add(port)

        vector = event.get("vector", "")
        if "FTP" in vector.upper():
            prof.targeted_services.add("FTP")
        if "SMB" in vector.upper():
            prof.targeted_services.add("SMB")
        if "SSH" in vector.upper():
            prof.targeted_services.add("SSH")
        if "TELNET" in vector.upper():
            prof.targeted_services.add("Telnet")

        prof.observed_techniques.add("T1003")

        dt = max(1, prof.last_seen_timestep - prof.first_seen_timestep + 1)
        prof.attack_velocity = prof.total_interactions / dt

    return profiles
