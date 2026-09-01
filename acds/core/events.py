"""
ACDS Real-Time Event Engine
Implements decoupled lifecycle event dispatching for network discovery, attack progression,
honeypot traps, risk changes, and defense mutations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import uuid


class EventType(str, Enum):
    # Discovery Events
    HOST_DISCOVERED = "HOST_DISCOVERED"
    SERVICE_DISCOVERED = "SERVICE_DISCOVERED"
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    OS_INFERRED = "OS_INFERRED"
    ASSET_CLASSIFIED = "ASSET_CLASSIFIED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"

    # Attack Simulation Events
    ATTACK_STARTED = "ATTACK_STARTED"
    INITIAL_COMPROMISE = "INITIAL_COMPROMISE"
    LATERAL_MOVEMENT_ATTEMPT = "LATERAL_MOVEMENT_ATTEMPT"
    TARGET_COMPROMISED = "TARGET_COMPROMISED"
    MOVEMENT_BLOCKED = "MOVEMENT_BLOCKED"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    HONEYPOT_TRIGGERED = "HONEYPOT_TRIGGERED"
    SIMULATION_COMPLETED = "SIMULATION_COMPLETED"

    # Risk & Defense Events
    RISK_UPDATED = "RISK_UPDATED"
    ADAPTIVE_RISK_MODIFIED = "ADAPTIVE_RISK_MODIFIED"
    DEFENSE_RECOMMENDED = "DEFENSE_RECOMMENDED"
    DEFENSE_SELECTED = "DEFENSE_SELECTED"
    DEFENSE_APPLIED = "DEFENSE_APPLIED"
    HOST_ISOLATED = "HOST_ISOLATED"
    PATCH_APPLIED = "PATCH_APPLIED"


@dataclass
class SystemEvent:
    """Strongly-typed system lifecycle event."""
    event_type: EventType
    source: str
    target: Optional[str]
    description: str
    severity: str = "INFO"  # 'INFO', 'WARNING', 'CRITICAL', 'SUCCESS'
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    utc_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "source": self.source,
            "target": self.target or "N/A",
            "description": self.description,
            "severity": self.severity,
            "metadata": self.metadata,
        }


class EventEngine:
    """Pub/Sub event dispatcher and audit log manager."""

    def __init__(self):
        self._history: List[SystemEvent] = []
        self._subscribers: List[Callable[[SystemEvent], None]] = []

    def subscribe(self, handler: Callable[[SystemEvent], None]) -> None:
        """Register an event listener."""
        if handler not in self._subscribers:
            self._subscribers.append(handler)

    def subscribe_all(self, handler: Callable[[SystemEvent], None]) -> None:
        """Alias for subscribe."""
        self.subscribe(handler)

    def unsubscribe(self, handler: Callable[[SystemEvent], None]) -> None:
        """Remove an event listener."""
        if handler in self._subscribers:
            self._subscribers.remove(handler)

    def dispatch(self, event: SystemEvent) -> None:
        """Dispatch a pre-constructed SystemEvent to all subscribers."""
        self._history.append(event)
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception:
                pass

    def publish(
        self,
        event_type: EventType,
        source: str,
        target: Optional[str] = None,
        description: str = "",
        severity: str = "INFO",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SystemEvent:
        """Emit an event to all subscribers and append to audit history."""
        event = SystemEvent(
            event_type=event_type,
            source=source,
            target=target,
            description=description,
            severity=severity,
            metadata=metadata or {},
        )
        self._history.append(event)
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception:
                pass  # Listener failures must never crash event engine
        return event

    def get_history(self, event_type: Optional[EventType] = None) -> List[SystemEvent]:
        """Retrieve recorded event history, optionally filtered by type."""
        if event_type is None:
            return list(self._history)
        return [e for e in self._history if e.event_type == event_type]

    def clear(self) -> None:
        """Clear recorded events."""
        self._history.clear()


# Global default event engine instance
default_event_engine = EventEngine()
