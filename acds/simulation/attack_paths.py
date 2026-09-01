"""
ACDS Attack Path Analysis Engine
Identifies longest routes, critical asset targeting paths, and bottleneck traversal points.
"""

from typing import Dict, List, Set, Tuple
import networkx as nx


def find_attack_paths_from_entry(
    G: nx.DiGraph,
    entry_node: str,
    max_paths: int = 10,
) -> List[List[str]]:
    """Compute shortest and critical paths from entry node to all reachable nodes."""
    if entry_node not in G:
        return []

    paths = []
    for target in G.nodes:
        if target == entry_node:
            continue
        try:
            if nx.has_path(G, entry_node, target):
                p = nx.shortest_path(G, entry_node, target)
                paths.append(p)
        except Exception:
            pass

    # Sort paths by length descending (deepest paths first)
    paths.sort(key=len, reverse=True)
    return paths[:max_paths]


def find_critical_paths(
    G: nx.DiGraph,
    entry_node: str,
) -> List[Tuple[List[str], str, int]]:
    """Find paths reaching high-value critical assets (Criticality >= 4)."""
    if entry_node not in G:
        return []

    critical_paths = []
    for node, data in G.nodes(data=True):
        if data.get("criticality", 0) >= 4 and node != entry_node:
            try:
                if nx.has_path(G, entry_node, node):
                    p = nx.shortest_path(G, entry_node, node)
                    critical_paths.append((p, node, data["criticality"]))
            except Exception:
                pass
    return critical_paths
