"""
ACDS v4.0 — PHASE 3: Adaptive Attack Simulation

Makes the attack graph dynamic. Whenever:
  - New asset discovered
  - Asset removed
  - New port opened
  - Port closed
  - Service changed
  - New CVE matched

Automatically:
  - Updates the graph (adds/removes nodes/edges)
  - Removes invalid paths
  - Creates new paths
  - Recalculates blast radius
  - Updates asset risk

Also maintains a historical topology timeline stored in SQLite.

SIMULATION ONLY — dynamic graph represents modeled paths, not real traffic.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from core.acds_logging import get_logger

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────
# TOPOLOGY CHANGE EVENT TYPES
# ─────────────────────────────────────────────────────────────────
TOPO_EVENT_NEW_ASSET = "NEW_ASSET"
TOPO_EVENT_REMOVED_ASSET = "REMOVED_ASSET"
TOPO_EVENT_NEW_PORT = "NEW_PORT"
TOPO_EVENT_CLOSED_PORT = "CLOSED_PORT"
TOPO_EVENT_SERVICE_CHANGE = "SERVICE_CHANGE"
TOPO_EVENT_NEW_CVE = "NEW_CVE"
TOPO_EVENT_GRAPH_UPDATED = "GRAPH_UPDATED"


def detect_topology_changes(
    prev_graph: Optional["nx.DiGraph"],
    curr_graph: "nx.DiGraph",
) -> List[Dict[str, Any]]:
    """
    Compare two graph snapshots and return a list of topology change events.
    Each event describes what changed and what graph update action was taken.
    """
    if prev_graph is None:
        return []

    changes = []
    now = datetime.now(timezone.utc).isoformat()

    prev_nodes = {data.get("ip"): n for n, data in prev_graph.nodes(data=True) if data.get("ip")}
    curr_nodes = {data.get("ip"): n for n, data in curr_graph.nodes(data=True) if data.get("ip")}

    # New assets
    for ip, node in curr_nodes.items():
        if ip not in prev_nodes:
            data = curr_graph.nodes[node]
            changes.append({
                "event_type": TOPO_EVENT_NEW_ASSET,
                "timestamp": now,
                "asset_ip": ip,
                "asset_display": data.get("display_name", node),
                "description": f"New asset discovered: {data.get('display_name', ip)} ({ip})",
                "graph_action": "NODE_ADDED",
                "severity": "MEDIUM",
            })

    # Removed assets
    for ip, node in prev_nodes.items():
        if ip not in curr_nodes:
            data = prev_graph.nodes[node]
            changes.append({
                "event_type": TOPO_EVENT_REMOVED_ASSET,
                "timestamp": now,
                "asset_ip": ip,
                "asset_display": data.get("display_name", node),
                "description": f"Asset removed/offline: {data.get('display_name', ip)} ({ip})",
                "graph_action": "NODE_REMOVED + ALL_EDGES_REMOVED",
                "severity": "LOW",
            })

    # Port/service changes on existing assets
    for ip in set(prev_nodes) & set(curr_nodes):
        prev_node = prev_nodes[ip]
        curr_node = curr_nodes[ip]
        prev_data = prev_graph.nodes[prev_node]
        curr_data = curr_graph.nodes[curr_node]

        prev_ports = set(prev_data.get("open_ports") or [])
        curr_ports = set(curr_data.get("open_ports") or [])

        for port in curr_ports - prev_ports:
            from app import PORT_SERVICE_MAP  # lazy import to avoid circular
            svc = PORT_SERVICE_MAP.get(port, "unknown")
            changes.append({
                "event_type": TOPO_EVENT_NEW_PORT,
                "timestamp": now,
                "asset_ip": ip,
                "asset_display": curr_data.get("display_name", curr_node),
                "port": port,
                "service": svc,
                "description": f"New port opened on {curr_data.get('display_name', ip)}: TCP/{port} ({svc})",
                "graph_action": "NEW_EDGES_ADDED",
                "severity": "HIGH",
            })

        for port in prev_ports - curr_ports:
            from app import PORT_SERVICE_MAP
            svc = PORT_SERVICE_MAP.get(port, "unknown")
            changes.append({
                "event_type": TOPO_EVENT_CLOSED_PORT,
                "timestamp": now,
                "asset_ip": ip,
                "asset_display": curr_data.get("display_name", curr_node),
                "port": port,
                "service": svc,
                "description": f"Port closed on {curr_data.get('display_name', ip)}: TCP/{port} ({svc})",
                "graph_action": "EDGES_REMOVED",
                "severity": "LOW",
            })

        # CVE changes
        prev_cve_ids = {c.get("cve_id") for c in (prev_data.get("cve_findings") or [])}
        curr_cve_ids = {c.get("cve_id") for c in (curr_data.get("cve_findings") or [])}
        new_cves = curr_cve_ids - prev_cve_ids
        for cve_id in new_cves:
            cve_data = next((c for c in curr_data.get("cve_findings", []) if c.get("cve_id") == cve_id), {})
            changes.append({
                "event_type": TOPO_EVENT_NEW_CVE,
                "timestamp": now,
                "asset_ip": ip,
                "asset_display": curr_data.get("display_name", curr_node),
                "cve_id": cve_id,
                "cvss": cve_data.get("cvss"),
                "description": f"New CVE on {curr_data.get('display_name', ip)}: {cve_id} (CVSS {cve_data.get('cvss', '?')})",
                "graph_action": "EDGE_WEIGHTS_UPDATED + RISK_RECALCULATED",
                "severity": "CRITICAL" if (cve_data.get("cvss") or 0) >= 7 else "HIGH",
            })

    return changes


def apply_topology_changes_to_graph(
    G: "nx.DiGraph",
    changes: List[Dict[str, Any]],
    get_lateral_edges_fn,  # callable: (open_ports) -> list of edge dicts
) -> Tuple["nx.DiGraph", List[str]]:
    """
    Apply detected topology change events to the live graph.
    Returns (updated_G, list_of_actions_taken).
    """
    actions_taken = []

    for change in changes:
        event_type = change.get("event_type")
        ip = change.get("asset_ip")

        if event_type == TOPO_EVENT_REMOVED_ASSET:
            # Find and remove node by IP
            to_remove = [n for n, d in G.nodes(data=True) if d.get("ip") == ip]
            for n in to_remove:
                G.remove_node(n)
                actions_taken.append(f"REMOVED node {n} ({ip}) + all attached edges")

        elif event_type == TOPO_EVENT_CLOSED_PORT:
            port = change.get("port")
            # Remove edges that used this port as the attack vector
            node = next((n for n, d in G.nodes(data=True) if d.get("ip") == ip), None)
            if node:
                edges_to_remove = [
                    (src, dst) for src, dst, d in G.edges(data=True)
                    if dst == node and d.get("access_port") == port
                ]
                for edge in edges_to_remove:
                    G.remove_edge(*edge)
                actions_taken.append(f"REMOVED {len(edges_to_remove)} edge(s) via closed port {port} on {ip}")

        elif event_type == TOPO_EVENT_NEW_PORT:
            port = change.get("port")
            # Add new edges TO this node from all other nodes
            node = next((n for n, d in G.nodes(data=True) if d.get("ip") == ip), None)
            if node and port:
                new_edge_count = 0
                node_data = G.nodes[node]
                open_ports = node_data.get("open_ports") or []
                if port not in open_ports:
                    open_ports.append(port)
                    G.nodes[node]["open_ports"] = open_ports

                edges_for_port = get_lateral_edges_fn([port])
                for src in G.nodes:
                    if src == node:
                        continue
                    for edge_info in edges_for_port:
                        if not G.has_edge(src, node):
                            G.add_edge(src, node,
                                       connection=edge_info.get("connection"),
                                       access_vector=edge_info.get("vector"),
                                       access_port=edge_info.get("port"),
                                       mitre_code=edge_info.get("mitre_code"),
                                       mitre_desc=edge_info.get("mitre_desc"),
                                       success_prob=edge_info.get("success_prob", 0.4),
                                       reachability="POTENTIAL REACHABILITY")
                            new_edge_count += 1
                actions_taken.append(f"ADDED {new_edge_count} new edge(s) for new port {port} on {ip}")

        elif event_type == TOPO_EVENT_NEW_CVE:
            # Update edge weights for edges TO this node
            node = next((n for n, d in G.nodes(data=True) if d.get("ip") == ip), None)
            if node:
                cve_id = change.get("cve_id")
                cvss = change.get("cvss") or 0
                new_prob = min(0.95, cvss / 10.0)
                updated = 0
                for src in G.predecessors(node):
                    for k, v in G[src][node].items():
                        G[src][node][k]["success_prob"] = new_prob
                        updated += 1
                actions_taken.append(f"UPDATED {updated} edge(s) success_prob for {cve_id} on {ip}")

    return G, actions_taken


def record_topology_snapshot(db_conn, G: "nx.DiGraph", trigger: str) -> None:
    """
    Persist a topology snapshot to SQLite for the historical timeline.
    Stores: node count, edge count, critical assets, avg risk, trigger.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        real_nodes = [(n, d) for n, d in G.nodes(data=True) if d.get("node_type") != "honeypot"]
        avg_risk = (
            sum(d.get("risk_score", 0) for _, d in real_nodes) / len(real_nodes)
            if real_nodes else 0
        )
        critical_count = sum(1 for _, d in real_nodes if d.get("criticality", 0) >= 4)
        edge_count = G.number_of_edges()

        db_conn.execute(
            """INSERT INTO topology_snapshots
               (timestamp, node_count, edge_count, critical_assets, avg_risk, trigger)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now, len(real_nodes), edge_count, critical_count, round(avg_risk, 2), trigger),
        )
        db_conn.commit()
    except Exception as exc:
        log.warning("Could not record topology snapshot: %s", exc)


def render_topology_change_html(changes: List[Dict[str, Any]]) -> str:
    """Render topology change events as styled HTML cards."""
    if not changes:
        return "<div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.7rem'>No topology changes detected.</div>"

    severity_colors = {
        "CRITICAL": "#ff3355", "HIGH": "#ff8c00", "MEDIUM": "#ffd700", "LOW": "#3d6a8a"
    }
    event_icons = {
        TOPO_EVENT_NEW_ASSET: "🟢", TOPO_EVENT_REMOVED_ASSET: "⚫",
        TOPO_EVENT_NEW_PORT: "🟠", TOPO_EVENT_CLOSED_PORT: "🔵",
        TOPO_EVENT_SERVICE_CHANGE: "🟡", TOPO_EVENT_NEW_CVE: "🔴",
    }

    cards = []
    for change in changes[:20]:
        sev = change.get("severity", "LOW")
        color = severity_colors.get(sev, "#3d6a8a")
        icon = event_icons.get(change.get("event_type", ""), "⚪")
        ts = (change.get("timestamp") or "")[:19].replace("T", " ")
        action = change.get("graph_action", "")

        cards.append(f"""
<div style='background:#0a1520;border-left:3px solid {color};padding:8px 12px;margin:4px 0;
     font-family:Share Tech Mono;font-size:0.7rem;'>
  <div style='display:flex;justify-content:space-between'>
    <span>{icon} <span style='color:{color}'>{sev}</span> — {change.get('description','')}</span>
    <span style='color:#3d6a8a;font-size:0.62rem'>{ts}</span>
  </div>
  <div style='color:#3d6a8a;font-size:0.62rem;margin-top:2px'>Graph action: {action} (SIMULATION)</div>
</div>""")

    return "\n".join(cards)
