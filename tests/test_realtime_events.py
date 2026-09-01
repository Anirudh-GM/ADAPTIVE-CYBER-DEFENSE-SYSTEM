"""
Real-time Event Engine & Incremental Step Generation Test.
Proves that events are emitted incrementally as the attack progresses and validates event ordering.
"""

import pytest
import networkx as nx
from acds.core.events import EventType, SystemEvent, EventEngine
from acds.core.graph import build_network
from acds.simulation.attack_engine import simulate_attack_step_generator


def test_realtime_event_incremental_generation_and_ordering():
    G = build_network()
    entry_point = "User-PC"
    engine = EventEngine()
    dispatched_events = []

    # Subscribe listener to all events
    engine.subscribe_all(lambda ev: dispatched_events.append(ev))

    # Run generator step by step
    generator = simulate_attack_step_generator(G, entry_node=entry_point, seed=42)

    step_count = 0
    previous_timestep = 0

    for step_dict, state, event in generator:
        step_count += 1
        engine.dispatch(event)

        # Verify event properties
        assert isinstance(event, SystemEvent)
        ts = event.metadata.get("timestep", 1)
        assert ts >= previous_timestep
        previous_timestep = ts
        assert event.timestamp is not None

        # Verify step dict matches event
        assert step_dict["timestep"] == ts
        assert step_dict["node"] in (event.target, event.source)

        # Verify state is updated incrementally
        if event.event_type == EventType.INITIAL_COMPROMISE:
            assert entry_point in state.compromised
            assert len(state.compromised) >= 1
        elif event.event_type == EventType.HONEYPOT_TRIGGERED:
            assert state.honeypot_triggered is True

    assert step_count > 0
    assert len(dispatched_events) == step_count

    # Verify first event is INITIAL_COMPROMISE
    assert dispatched_events[0].event_type == EventType.INITIAL_COMPROMISE
    assert dispatched_events[0].target == entry_point

    # Verify all events have non-empty descriptions
    for ev in dispatched_events:
        assert len(ev.description) > 0
