"""
ACDS Heuristic / Greedy Defense Optimizer
Selects the highest-efficiency defense actions within resource/budget constraints.
"""

from typing import Dict, List, Tuple, Any
from acds.core.constants import DEFENSE_STATE_SELECTED


def greedy_defense_selection(
    actions: List[Dict[str, Any]],
    budget: int,
) -> Tuple[List[Dict[str, Any]], float, int]:
    """
    Greedy knapsack selection: selects defense actions in descending order of efficiency
    (risk_reduction / cost) without exceeding the allocated budget.

    Returns:
        (selected_actions, total_risk_reduction, remaining_budget)
    """
    selected = []
    remaining_budget = budget
    total_reduction = 0.0

    # Ensure actions are sorted by efficiency descending
    sorted_actions = sorted(actions, key=lambda x: x.get("efficiency", 0.0), reverse=True)

    for action in sorted_actions:
        cost = action.get("cost", 0)
        if cost <= remaining_budget:
            sel_action = {**action, "state": DEFENSE_STATE_SELECTED}
            selected.append(sel_action)
            remaining_budget -= cost
            total_reduction += action.get("risk_reduction", 0.0)

    return selected, round(total_reduction, 1), remaining_budget
