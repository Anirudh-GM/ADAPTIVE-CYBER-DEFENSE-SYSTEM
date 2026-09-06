"""
ADAPTIVE HONEYPOT ENGINE — core/honeypot_engine.py
─────────────────────────────────────────────────────────────────
Priority 19 (CORE feature per synopsis): the existing app already
has a *static* honeypot decoy node inside the attack simulation
(a single boolean 'honeypot_triggered' with a flat +15 penalty that
resets every run). That demonstrates deception, but not the
ADAPTIVE feedback loop the synopsis requires:

    Honeypot activity observed
            -> threat signal increases
            -> related asset/path risk adjusted
            -> defense recommendations re-prioritized

This module adds a PERSISTENT event log (via data/database.py) and a
transparent, rule-based (explicitly NOT machine learning) adaptive
signal computed from that history:

  - Every time the simulator triggers the honeypot, an event row is
    written (source node, decoy touched, timestamp).
  - compute_adaptive_signal() looks at how many events happened in a
    recent rolling window and returns a 0-1 "threat signal" plus a
    human-readable reason.
  - apply_adaptive_feedback() takes a base risk score and nudges it
    using that signal, capped so a single burst of activity cannot
    push risk past 100 and old inactivity naturally lets the signal
    decay back toward 0 (events outside the window stop counting).

This is explicitly rule-based adaptive scoring, not ML — the UI
must say so, per spec Priority 19/9.
"""

from datetime import datetime, timezone

from data import database

# How many recent events, within how many hours, define "active" honeypot
# interaction. Configurable constants (Priority 9: transparent weights).
ADAPTIVE_WINDOW_HOURS = 24
ADAPTIVE_MAX_BOOST = 15.0          # matches the existing flat +15 single-event penalty
ADAPTIVE_PER_EVENT_BOOST = 3.0     # each additional event within the window adds this much
ADAPTIVE_EVENTS_FOR_MAX = 5        # events at/above this count within the window -> full boost


def record_trigger(source_node, decoy_node, event_type, details, risk_before, risk_after,
                    db_path=database.DEFAULT_DB_PATH):
    """Persist one honeypot interaction. Called whenever the attack
    simulator's honeypot_triggered flag flips True for a run."""
    database.log_honeypot_event(
        source=source_node, decoy=decoy_node, event_type=event_type,
        details=details, risk_before=risk_before, risk_after=risk_after,
        db_path=db_path,
    )


def _events_in_window(hours=ADAPTIVE_WINDOW_HOURS, db_path=database.DEFAULT_DB_PATH):
    events = database.get_honeypot_events(limit=500, db_path=db_path)
    if not events:
        return []
    now = datetime.now(timezone.utc)
    recent = []
    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
        except (ValueError, TypeError):
            continue
        age_hours = (now - ts).total_seconds() / 3600.0
        if age_hours <= hours:
            recent.append(e)
    return recent


def compute_adaptive_signal(db_path=database.DEFAULT_DB_PATH):
    """Returns dict: {signal(0-1), event_count, window_hours, reason}."""
    recent = _events_in_window(db_path=db_path)
    count = len(recent)
    signal = min(1.0, count / ADAPTIVE_EVENTS_FOR_MAX) if count else 0.0

    if count == 0:
        reason = "No honeypot interactions recorded in the last {}h — adaptive signal quiet.".format(
            ADAPTIVE_WINDOW_HOURS)
    elif count == 1:
        reason = "1 honeypot interaction in the last {}h — isolated probe, minimal adaptive impact.".format(
            ADAPTIVE_WINDOW_HOURS)
    else:
        reason = (f"{count} honeypot interactions in the last {ADAPTIVE_WINDOW_HOURS}h — "
                   f"repeated decoy interaction pattern, adaptive risk signal elevated.")

    return {
        "signal": round(signal, 2),
        "event_count": count,
        "window_hours": ADAPTIVE_WINDOW_HOURS,
        "reason": reason,
        "method": "rule-based (event frequency within a rolling window) — not machine learning",
    }


def apply_adaptive_feedback(base_risk, db_path=database.DEFAULT_DB_PATH):
    """Nudge a base 0-100 risk score using the persistent adaptive signal.

    boost = min(ADAPTIVE_MAX_BOOST, signal_info['event_count'] * ADAPTIVE_PER_EVENT_BOOST)
    Returns dict with adjusted_risk, boost, and the signal_info for display.
    """
    info = compute_adaptive_signal(db_path=db_path)
    boost = min(ADAPTIVE_MAX_BOOST, info["event_count"] * ADAPTIVE_PER_EVENT_BOOST)
    adjusted = min(100.0, base_risk + boost)
    return {
        "base_risk": base_risk,
        "boost": round(boost, 1),
        "adjusted_risk": round(adjusted, 1),
        **info,
    }
