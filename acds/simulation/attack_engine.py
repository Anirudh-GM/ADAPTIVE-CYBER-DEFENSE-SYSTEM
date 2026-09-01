"""
ACDS Time-Based Attack Simulation Engine
Implements step-by-step probabilistic lateral movement, privilege escalation,
honeypot decoy trapping, MITRE ATT&CK mapping, and event-driven progression.
"""

from collections import deque
import random
from typing import Dict, Iterator, List, Optional, Set, Tuple, Any
import networkx as nx

from acds.core.events import EventType, SystemEvent, default_event_engine
from acds.simulation.attack_state import AttackProgressState


def simulate_attack_step_generator(
    G: nx.DiGraph,
    entry_node: str,
    seed: Optional[int] = 42,
    ids_deployed: bool = False,
    segmentation_applied: bool = False,
) -> Iterator[Tuple[Dict[str, Any], AttackProgressState, SystemEvent]]:
    """
    Step-by-step generator for true real-time event-driven simulation.
    Yields (timeline_entry, progress_state, lifecycle_event) at each progression step.
    """
    if seed is not None:
        random.seed(seed)

    state = AttackProgressState()

    if entry_node not in G.nodes:
        state.is_complete = True
        return

    entry_data = G.nodes[entry_node]
    state.compromised.add(entry_node)
    G.nodes[entry_node]["compromised"] = True

    initial_entry = {
        "node": entry_node,
        "from_node": None,
        "timestep": 1,
        "mitre_code": "T1078",
        "mitre_desc": "Initial Access — foothold on entry system",
        "access_vector": "Initial compromise / phishing / stolen credentials",
        "success": True,
        "vuln": entry_data.get("vulnerability", 0.3),
        "criticality": entry_data.get("criticality", 2),
        "ntype": entry_data.get("node_type", "endpoint"),
        "priv_esc": False,
    }
    state.timeline.append(initial_entry)
    state.attack_paths.append([entry_node])
    state.visited.add(entry_node)
    state.current_node = entry_node

    init_event = default_event_engine.publish(
        event_type=EventType.INITIAL_COMPROMISE,
        source="Simulated Attacker",
        target=entry_node,
        description=f"Initial foothold established on {entry_node}",
        severity="CRITICAL",
        metadata={"timestep": 1, "mitre": "T1078"},
    )
    yield initial_entry, state, init_event

    queue = deque([(entry_node, 1, [entry_node])])

    global_dampener = 1.0
    if ids_deployed:
        global_dampener *= 0.75
    if segmentation_applied:
        global_dampener *= 0.55

    while queue:
        current_node, timestep, path = queue.popleft()
        if current_node not in state.compromised:
            continue

        for neighbor in G.successors(current_node):
            if neighbor in state.visited:
                continue
            nd = G.nodes[neighbor]

            # Blocked by isolation defense
            if nd.get("isolated"):
                state.visited.add(neighbor)
                blocked_entry = {
                    "node": neighbor,
                    "from_node": current_node,
                    "timestep": timestep + 1,
                    "mitre_code": "T1599",
                    "mitre_desc": "Network Boundary Bridging — blocked",
                    "access_vector": "Blocked by applied isolation/segmentation defense",
                    "success": False,
                    "vuln": nd.get("vulnerability", 0.0),
                    "criticality": nd.get("criticality", 2),
                    "ntype": nd.get("node_type", "endpoint"),
                    "priv_esc": False,
                }
                state.timeline.append(blocked_entry)
                block_event = default_event_engine.publish(
                    event_type=EventType.MOVEMENT_BLOCKED,
                    source=current_node,
                    target=neighbor,
                    description=f"Lateral movement from {current_node} to {neighbor} blocked by defense isolation",
                    severity="INFO",
                    metadata={"timestep": timestep + 1, "mitre": "T1599"},
                )
                yield blocked_entry, state, block_event
                continue

            edge = G.edges[current_node, neighbor]
            ntype = nd.get("node_type", "endpoint")

            if ntype == "honeypot":
                prob = nd.get("vulnerability", 0.5)
                mitre_code, mitre_desc = "T1003", "OS Credential Dumping [TRAP]"
                access_vector = edge.get("access_vector", "Honeypot probe")
            else:
                prob = min(0.95, edge.get("success_prob", 0.4) * nd.get("vulnerability", 0.3) * global_dampener)
                if nd.get("criticality", 2) >= 4:
                    prob *= 0.85
                mitre_code = edge.get("mitre_code", "T1021")
                mitre_desc = edge.get("mitre_desc", "Lateral Movement")
                access_vector = edge.get("access_vector", edge.get("connection", "network"))

            success = random.random() < prob
            state.visited.add(neighbor)
            actual_timestep = timestep + 1
            did_priv_esc = False
            state.current_node = neighbor

            if success:
                state.compromised.add(neighbor)
                G.nodes[neighbor]["compromised"] = True
                new_path = path + [neighbor]
                state.attack_paths.append(new_path)
                queue.append((neighbor, actual_timestep, new_path))

                if ntype == "honeypot":
                    state.honeypot_triggered = True
                    hp_obs = {
                        "source": current_node,
                        "honeypot": neighbor,
                        "port": edge.get("access_port", 21),
                        "vector": access_vector,
                        "timestep": actual_timestep,
                    }
                    state.honeypot_events.append(hp_obs)
                    hp_event = default_event_engine.publish(
                        event_type=EventType.HONEYPOT_TRIGGERED,
                        source=current_node,
                        target=neighbor,
                        description=f"Honeypot decoy {neighbor} triggered by probe from {current_node}",
                        severity="CRITICAL",
                        metadata=hp_obs,
                    )

                step_entry = {
                    "node": neighbor,
                    "from_node": current_node,
                    "timestep": actual_timestep,
                    "mitre_code": mitre_code,
                    "mitre_desc": mitre_desc,
                    "access_vector": access_vector,
                    "success": True,
                    "vuln": nd.get("vulnerability", 0.0),
                    "criticality": nd.get("criticality", 2),
                    "ntype": ntype,
                    "priv_esc": False,
                }
                state.timeline.append(step_entry)
                step_event = default_event_engine.publish(
                    event_type=EventType.TARGET_COMPROMISED,
                    source=current_node,
                    target=neighbor,
                    description=f"Target {neighbor} compromised via {access_vector}",
                    severity="CRITICAL",
                    metadata={"timestep": actual_timestep, "mitre": mitre_code},
                )
                yield step_entry, state, step_event

                if nd.get("criticality", 2) >= 4 and neighbor not in state.priv_escalated:
                    state.priv_escalated.add(neighbor)
                    G.nodes[neighbor]["priv_escalated"] = True
                    did_priv_esc = True
                    priv_entry = {
                        "node": neighbor,
                        "from_node": current_node,
                        "timestep": actual_timestep + 1,
                        "mitre_code": "T1068",
                        "mitre_desc": "Privilege Escalation — admin/root on high-value system",
                        "access_vector": "Credential dump / sudo / token theft",
                        "success": True,
                        "vuln": nd.get("vulnerability", 0.0),
                        "criticality": nd.get("criticality", 2),
                        "ntype": ntype,
                        "priv_esc": True,
                    }
                    state.timeline.append(priv_entry)
                    priv_event = default_event_engine.publish(
                        event_type=EventType.PRIVILEGE_ESCALATION,
                        source=current_node,
                        target=neighbor,
                        description=f"Privilege escalation on high-value system {neighbor}",
                        severity="CRITICAL",
                        metadata={"timestep": actual_timestep + 1, "mitre": "T1068"},
                    )
                    yield priv_entry, state, priv_event
            else:
                fail_entry = {
                    "node": neighbor,
                    "from_node": current_node,
                    "timestep": actual_timestep,
                    "mitre_code": mitre_code,
                    "mitre_desc": mitre_desc,
                    "access_vector": access_vector,
                    "success": False,
                    "vuln": nd.get("vulnerability", 0.0),
                    "criticality": nd.get("criticality", 2),
                    "ntype": ntype,
                    "priv_esc": False,
                }
                state.timeline.append(fail_entry)
                fail_event = default_event_engine.publish(
                    event_type=EventType.LATERAL_MOVEMENT_ATTEMPT,
                    source=current_node,
                    target=neighbor,
                    description=f"Lateral movement attempt from {current_node} to {neighbor} failed",
                    severity="INFO",
                    metadata={"timestep": actual_timestep, "mitre": mitre_code},
                )
                yield fail_entry, state, fail_event

    state.is_complete = True
    state.timeline.sort(key=lambda x: x["timestep"])


def simulate_attack(
    G: nx.DiGraph,
    entry_node: str,
    seed: Optional[int] = 42,
    ids_deployed: bool = False,
    segmentation_applied: bool = False,
) -> Tuple[List[Dict[str, Any]], Set[str], bool, Dict[str, Any]]:
    """
    Run attack simulation to completion and return (timeline, compromised_set, honeypot_triggered, stats).
    Preserves exact legacy signature for full frontend compatibility.
    """
    gen = simulate_attack_step_generator(
        G, entry_node, seed=seed,
        ids_deployed=ids_deployed,
        segmentation_applied=segmentation_applied,
    )

    final_state = None
    for entry, state, event in gen:
        final_state = state

    if not final_state:
        return [], set(), False, {}

    timeline = final_state.timeline
    compromised = final_state.compromised
    honeypot_triggered = final_state.honeypot_triggered

    real_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    real_compromised = [n for n in compromised if G.nodes[n].get("node_type") != "honeypot"]
    critical_reached = [n for n in real_compromised if G.nodes[n].get("criticality", 2) >= 4]
    max_hops = max((len(p) - 1 for p in final_state.attack_paths), default=0)

    stats = {
        "systems_controlled": len(real_compromised),
        "total_systems": len(real_nodes),
        "max_lateral_hops": max_hops,
        "privilege_escalations": len(final_state.priv_escalated),
        "attack_paths": final_state.attack_paths[:10],
        "reachable_from_entry": len(real_compromised),
        "critical_assets_reached": len(critical_reached),
        "honeypot_observations": final_state.honeypot_events,
    }
    return timeline, compromised, honeypot_triggered, stats
