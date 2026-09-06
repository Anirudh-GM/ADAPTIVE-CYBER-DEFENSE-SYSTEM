"""
ACDS v3.0 — SPRINT 3, PHASE 7: OPERATIONAL RELIABILITY — LOGGING
core/acds_logging.py
─────────────────────────────────────────────────────────────────
One shared logger configuration for the whole app: a rotating file
handler (so a long-running monitoring session never grows an
unbounded log file) plus a console handler at WARNING+ so operators
running `streamlit run app.py` in a terminal still see problems live.

Stdlib-only, no Streamlit import — safe to use from core/*.py modules
that must stay independently testable, and from app.py itself.

Usage:
    from core.acds_logging import get_logger
    log = get_logger(__name__)
    log.warning("NVD lookup failed for %s: %s", version_string, exc)
"""

import logging
import logging.handlers
import os

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
LOG_PATH = os.path.join(LOG_DIR, "acds.log")

_configured = False


def _configure_root():
    global _configured
    if _configured:
        return
    os.makedirs(LOG_DIR, exist_ok=True)
    root = logging.getLogger("acds")
    root.setLevel(logging.INFO)

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
        root.addHandler(file_handler)
    except OSError:
        # A read-only filesystem or permissions issue must never prevent
        # the app itself from starting — fall back to console-only.
        pass

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter("[ACDS] %(levelname)s %(name)s: %(message)s"))
    root.addHandler(console_handler)

    root.propagate = False
    _configured = True


def get_logger(name="acds"):
    """Return a logger under the shared 'acds' namespace, configured on
    first use. Safe to call repeatedly/from multiple modules."""
    _configure_root()
    if not name.startswith("acds"):
        name = f"acds.{name}"
    return logging.getLogger(name)
