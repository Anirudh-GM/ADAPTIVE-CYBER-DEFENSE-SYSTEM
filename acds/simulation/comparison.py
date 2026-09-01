"""
ACDS Simulation Comparison Engine
Compares baseline (pre-defense) and post-defense simulation runs to measure
exact risk reduction, preserved critical assets, restricted hops, and defense effectiveness.
"""

from typing import Dict, List, Optional, Any
from acds.core.models import ComparisonResult, DefenseAction


def compare_simulations(
    before_risk: float,
    after_risk: float,
    before_blast: Dict[str, Any],
    after_blast: Dict[str, Any],
    budget_used: int = 0,
    applied_actions: Optional[List[DefenseAction]] = None,
) -> ComparisonResult:
    """
    Compare pre-defense and post-defense simulation metrics.
    """
    if before_risk > 0:
        reduction_pct = round(max(0.0, (before_risk - after_risk) / before_risk * 100.0), 1)
    else:
        reduction_pct = 0.0

    comp_before = before_blast.get('systems_controlled', before_blast.get('compromised_count', 0))
    comp_after = after_blast.get('systems_controlled', after_blast.get('compromised_count', 0))

    crit_before = before_blast.get('critical_assets_reached', 0)
    crit_after = after_blast.get('critical_assets_reached', 0)

    depth_before = before_blast.get('max_lateral_hops', 0)
    depth_after = after_blast.get('max_lateral_hops', 0)

    return ComparisonResult(
        risk_before=before_risk,
        risk_after=after_risk,
        risk_reduction_pct=reduction_pct,
        systems_compromised_before=comp_before,
        systems_compromised_after=comp_after,
        critical_reached_before=crit_before,
        critical_reached_after=crit_after,
        max_depth_before=depth_before,
        max_depth_after=depth_after,
        budget_used=budget_used,
        applied_actions=applied_actions or [],
    )
