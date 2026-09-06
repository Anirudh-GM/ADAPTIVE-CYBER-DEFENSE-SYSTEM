"""
ACDS v3.0 — SPRINT 2 — PHASE 2/3: NETWORK EXPOSURE SCORE
core/network_exposure.py
─────────────────────────────────────────────────────────────────
Pure graph-topology logic — no Streamlit, no SQLite. Takes the live
NetworkX graph (already built by build_dynamic_graph()/build_network()
in app.py, with directed "POTENTIAL REACHABILITY" lateral-movement
edges) and derives:

  - a per-asset Network Exposure component (Phase 2), replacing the
    single-number "how many other assets exist" placeholder with real
    graph measurements: reachable assets, reachable-FROM count,
    degree centrality, and exposed sensitive lateral-movement services.
  - an organization-wide Network Exposure figure (mean of the above)
    and a Critical Asset Exposure figure, both consumed by
    calculate_overall_acds_risk() in app.py for the Phase 3 Overall
    ACDS Risk formula.

PRIORITY 26 BOUNDARY: everything here is POTENTIAL REACHABILITY derived
from modeled lateral-movement edges (open service -> possible access),
never OBSERVED network traffic. No packets are sent from this module.
"""

# Cap constants documented here (Phase 2 requirement: "no hidden
# calculations") rather than buried as magic numbers.
REACHABLE_ASSETS_CAP = 5          # reaching this many other assets = fully exposed on this sub-component
SENSITIVE_LATERAL_CAP = 4         # this many sensitive lateral-movement ports open = fully exposed
CENTRALITY_FULL_EXPOSURE = 0.5    # degree centrality of 0.5+ is treated as maximally central

# Sub-component weights within the single Network Exposure score
# (Phase 2) — documented, must sum to 1.0.
_W_REACHABLE = 0.45
_W_SENSITIVE = 0.30
_W_CENTRALITY = 0.25


def _degree_centrality(G, node):
    """Simple degree centrality: (in-degree + out-degree) / (2 * (N-1)).
    Equivalent to networkx.degree_centrality() for a DiGraph but computed
    directly from the graph's own degree views so this module has no
    hard dependency on the networkx algorithms module."""
    n = G.number_of_nodes()
    if n <= 1:
        return 0.0
    total_other = n - 1
    deg = G.in_degree(node) + G.out_degree(node)
    return deg / (2 * total_other)


def compute_node_network_exposure(G, node, sensitive_ports):
    """Phase 2: per-asset Network Exposure component.

    Measures (documented, no observed traffic):
      - reachable_assets   : how many OTHER assets this node can
                              potentially reach (out-degree in the
                              modeled reachability graph)
      - reachable_from     : how many OTHER assets can potentially
                              reach this node (in-degree)
      - degree_centrality   : this node's share of all modeled
                              reachability edges in the network
      - sensitive_lateral_services : open ports on THIS node that are
                              commonly abused for lateral movement
    """
    data = G.nodes[node]
    out_deg = G.out_degree(node)
    in_deg = G.in_degree(node)
    centrality = round(_degree_centrality(G, node), 3)

    open_ports = data.get('open_ports') or []
    sensitive_open = sorted(set(open_ports) & sensitive_ports)

    reach_score = min(out_deg / REACHABLE_ASSETS_CAP, 1.0) * 100
    sensitive_score = min(len(sensitive_open) / SENSITIVE_LATERAL_CAP, 1.0) * 100
    centrality_score = min(centrality / CENTRALITY_FULL_EXPOSURE, 1.0) * 100

    total = (reach_score * _W_REACHABLE) + (sensitive_score * _W_SENSITIVE) + (centrality_score * _W_CENTRALITY)
    total = max(0.0, min(100.0, total))

    return {
        'score': round(total, 1),
        'reachable_assets': out_deg,
        'reachable_from': in_deg,
        'degree_centrality': centrality,
        'sensitive_lateral_services': sensitive_open,
        'basis': (f'Reaches {out_deg} asset(s), reachable from {in_deg}, '
                  f'degree centrality {centrality}, {len(sensitive_open)} sensitive lateral service(s)'),
        'reachability_note': 'POTENTIAL REACHABILITY (modeled) — not observed network traffic',
    }


def apply_network_exposure_scores(G, sensitive_ports, recompute_fn):
    """Mutates every non-honeypot node's risk_components['network_exposure']
    using real graph topology (Phase 2), then calls recompute_fn(node_data)
    (app.py's recompute_node_risk) so the Priority-6 Asset Risk total stays
    consistent with the new component (Priority 18 requirement: components
    must always actually feed the score, never be cosmetic only)."""
    for node, data in G.nodes(data=True):
        if data.get('node_type') == 'honeypot':
            continue
        ne = compute_node_network_exposure(G, node, sensitive_ports)
        comps = data.get('risk_components') or {}
        existing_weight = comps.get('network_exposure', {}).get('weight', 0.10)
        comps['network_exposure'] = {
            'normalized_score': ne['score'],
            'weight': existing_weight,
            'contribution': 0.0,  # recompute_fn fills this in from weight * score
        }
        data['risk_components'] = comps
        data['network_exposure_detail'] = ne
        if 'risk_components' in data:
            recompute_fn(data)
    return G


def calculate_critical_asset_exposure(G):
    """Phase 3 input: fraction (0-100) of CRITICAL/HIGH-criticality assets
    (criticality level >= 4) that are exposed — either reachable from at
    least one other discovered asset, or directly expose at least one
    open service themselves."""
    critical_nodes = [
        n for n, d in G.nodes(data=True)
        if d.get('node_type') != 'honeypot' and (d.get('criticality') or 0) >= 4
    ]
    if not critical_nodes:
        return {'score': 0.0, 'exposed_count': 0, 'critical_count': 0,
                'basis': 'No CRITICAL/HIGH-criticality assets discovered'}

    exposed = [
        n for n in critical_nodes
        if G.in_degree(n) > 0 or bool(G.nodes[n].get('open_ports'))
    ]
    score = round(len(exposed) / len(critical_nodes) * 100, 1)
    return {
        'score': score, 'exposed_count': len(exposed), 'critical_count': len(critical_nodes),
        'exposed_assets': [G.nodes[n].get('ip') for n in exposed],
        'basis': f'{len(exposed)} of {len(critical_nodes)} critical asset(s) reachable or service-exposed',
    }


def calculate_network_exposure_component(G):
    """Phase 3 input: organization-wide Network Exposure figure = mean of
    every non-honeypot asset's Phase-2 network_exposure normalized score."""
    scores = []
    for n, d in G.nodes(data=True):
        if d.get('node_type') == 'honeypot':
            continue
        comp = (d.get('risk_components') or {}).get('network_exposure')
        if comp and comp.get('normalized_score') is not None:
            scores.append(comp['normalized_score'])
    if not scores:
        return {'score': 0.0, 'basis': 'No network exposure data available yet'}
    return {'score': round(sum(scores) / len(scores), 1),
            'basis': f'Mean modeled network exposure across {len(scores)} asset(s)'}
