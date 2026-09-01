"""
ACDS Defense Policy & Rules Engine
Defines defense action types, states, cost parameters, and execution validation.
"""

from typing import Dict, List, Set, Any
from acds.core.constants import (
    DEFENSE_STATE_RECOMMENDED,
    DEFENSE_STATE_SELECTED,
    DEFENSE_STATE_APPLIED,
)


def validate_defense_action(action: Dict[str, Any]) -> bool:
    """Validate that a defense action dictionary contains all mandatory keys."""
    required = {"action", "node", "type", "cost", "risk_reduction", "efficiency", "description", "state"}
    return required.issubset(action.keys()) and action.get("cost", 0) > 0
