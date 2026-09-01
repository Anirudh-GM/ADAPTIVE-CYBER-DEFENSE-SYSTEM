# REAL-TIME EVENT ENGINE & LIFECYCLE DISPATCHER

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. Event-Driven Architecture

ACDS incorporates a decoupled publisher-subscriber event pipeline in `acds.core.events.EventEngine`. The simulation engine does not simply compute the final state and dump it to the UI; rather, it executes as an **incremental generator** (`simulate_attack_step_generator`) emitting discrete lifecycle events as the attacker explores the network graph.

```
       [ATTACK INITIATION]
                │
                ▼
      [SystemEvent: ATTACK_STARTED] ──> [EventEngine Listener / UI Dispatcher]
                │
                ▼
      [SystemEvent: INITIAL_COMPROMISE] ──> [Update Foothold Node Visual State]
                │
                ▼
      [SystemEvent: LATERAL_PROBE] ──> [Animate Traversal Edge]
                │
                ├──> [SystemEvent: TARGET_COMPROMISED] ──> [Update Compromised State]
                │
                ├──> [SystemEvent: HONEYPOT_TRIGGERED] ──> [Spring Decoy Trap & Telemetry]
                │
                └──> [SystemEvent: BOUNDARY_BLOCKED] ──> [Halt Traversal on Isolated Node]
                │
                ▼
      [SystemEvent: PRIVILEGE_ESCALATED] ──> [Escalate Root/Admin Privileges]
                │
                ▼
      [SystemEvent: ATTACK_COMPLETED] ──> [Finalize Blast Radius & Risk Synthesis]
```

---

## 2. Strongly-Typed Event Schema

Each event dispatched across the system adheres to the `SystemEvent` dataclass:

```python
@dataclass
class SystemEvent:
    event_type: EventType
    timestep: int
    source_node: Optional[str]
    target_node: Optional[str]
    technique_id: str
    technique_name: str
    success: bool
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
```

### Event Types:
- `ATTACK_STARTED`: Triggered when an attack simulation begins.
- `INITIAL_COMPROMISE`: Foothold gained on selected entry point.
- `LATERAL_PROBE`: Attacker probes an adjacent network service.
- `TARGET_COMPROMISED`: Target node compromised via open service.
- `PRIVILEGE_ESCALATED`: Attacker elevates permissions on high-value system.
- `HONEYPOT_TRIGGERED`: Attacker interacts with decoy node (MITRE T1003 trap).
- `BOUNDARY_BLOCKED`: Traversal rejected by network isolation / ACLs (MITRE T1599).
- `CRITICAL_ASSET_REACHED`: High-value crown jewel accessed.
- `ATTACK_COMPLETED`: Traversal queue exhausted or max hops reached.

---

## 3. UI Synchronization

The Streamlit UI consumes these events incrementally through the step generator, updating the in-memory graph, animating active nodes (`current_anim_node`), and synchronizing session state in real-time.
