"""
ACDS PyVis Graph Visualization Adapter
Generates cyberpunk-themed interactive directed network graph HTML.
"""

import os
import tempfile
from typing import Optional, Set
import networkx as nx
from pyvis.network import Network


def render_graph(
    G: nx.DiGraph,
    compromised_set: Optional[Set[str]] = None,
    current_node: Optional[str] = None,
    show_honeypot: bool = True,
) -> str:
    """Render interactive PyVis network graph with cyber aesthetic."""
    if compromised_set is None:
        compromised_set = set()

    net = Network(height="480px", width="100%", bgcolor="#050a0f", font_color="#7ab8d4", directed=True)
    net.set_options("""
    {
      "nodes": { "borderWidth": 2, "shadow": {"enabled": true, "size": 15},
                 "font": {"size": 13, "face": "Share Tech Mono"} },
      "edges": { "arrows": {"to": {"enabled": true, "scaleFactor": 0.8}},
                 "color": {"color": "#1a3a5c", "highlight": "#00d4ff"},
                 "smooth": {"type": "curvedCW", "roundness": 0.2}, "width": 1.5,
                 "shadow": {"enabled": false} },
      "physics": { "enabled": true, "barnesHut": {"gravitationalConstant": -4000,
                   "centralGravity": 0.4, "springLength": 140, "springConstant": 0.04, "damping": 0.09} },
      "interaction": { "hover": true, "tooltipDelay": 100 }
    }
    """)

    type_shapes = {
        "perimeter": "diamond",
        "endpoint": "dot",
        "server": "square",
        "database": "database",
        "honeypot": "star",
    }

    for node, data in G.nodes(data=True):
        ntype = data.get("node_type", "endpoint")
        is_compromised = node in compromised_set
        is_current = node == current_node
        is_honeypot = ntype == "honeypot"
        is_isolated = data.get("isolated", False)
        if not show_honeypot and is_honeypot:
            continue

        if is_current:
            color = {"background": "#ff8c00", "border": "#ffd700", "highlight": {"background": "#ffaa33"}}
            size = 32
        elif is_compromised and is_honeypot:
            color = {"background": "#ff3355", "border": "#ffd700", "highlight": {"background": "#ff5577"}}
            size = 28
        elif is_compromised:
            color = {"background": "#6b0018", "border": "#ff3355", "highlight": {"background": "#cc0033"}}
            size = 26
        elif is_honeypot:
            color = {"background": "#3d2800", "border": "#ffd700", "highlight": {"background": "#5a3d00"}}
            size = 22
        elif is_isolated:
            color = {"background": "#0a2e1a", "border": "#00ff88", "highlight": {"background": "#0f3d22"}}
            size = 22
        else:
            color = {"background": "#002d4a", "border": "#00d4ff", "highlight": {"background": "#003d60"}}
            size = 22

        cves = data.get('cve_findings', [])
        cve_html = ''.join(f"CONFIRMED: {c.get('cve_id')} (CVSS {c.get('cvss')})<br>" for c in cves[:2])
        status_label = (
            '🔴 COMPROMISED (simulated)' if is_compromised else
            '🟢 ISOLATED (defense applied)' if is_isolated else
            '🟡 HONEYPOT (decoy)' if is_honeypot else '🔵 OBSERVED ASSET'
        )
        tooltip = (
            f"<div style='font-family:Share Tech Mono;font-size:11px;color:#e0f4ff;background:#0d1f2d;padding:8px;border:1px solid #1a3a5c'>"
            f"<b style='color:#00d4ff'>{node}</b><br>IP: {data.get('ip')}<br>Role: {data.get('role')}<br>"
            f"Criticality: {data.get('criticality_label','?')} ({'★' * data.get('criticality', 2)})<br>"
            f"Asset Risk: {data.get('risk_score', int(data.get('vulnerability',0)*100))}/100 ({data.get('risk_severity','?')})<br>"
            f"{cve_html}"
            f"Status: {status_label}</div>"
        )

        short_label = node if "\n" in node else node.replace("-", "\n")
        net.add_node(
            node,
            label=short_label,
            title=tooltip,
            color=color,
            size=size,
            shape=type_shapes.get(ntype, "dot"),
        )

    for src, dst, data in G.edges(data=True):
        if not show_honeypot and (G.nodes[src].get("node_type") == "honeypot" or G.nodes[dst].get("node_type") == "honeypot"):
            continue
        src_comp, dst_comp = src in compromised_set, dst in compromised_set
        if src_comp and dst_comp:
            edge_color, width = "#ff3355", 3
        elif src_comp:
            edge_color, width = "#ff8c00", 2
        else:
            edge_color, width = "#1a3a5c", 1.5
        edge_title = f"{data.get('connection','')} — POTENTIAL REACHABILITY (modeled, not observed traffic)"
        net.add_edge(src, dst, title=edge_title, color=edge_color, width=width)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html", dir=tempfile.gettempdir())
    net.save_graph(tmp.name)
    tmp.close()
    with open(tmp.name, "r", encoding="utf-8") as f:
        html = f.read()
    try:
        os.unlink(tmp.name)
    except OSError:
        pass
    html = html.replace("body {", "body { background-color: #050a0f !important; margin: 0; padding: 0; ")
    return html
