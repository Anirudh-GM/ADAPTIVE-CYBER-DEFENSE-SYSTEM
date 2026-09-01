# ACDS AUTOMATED TESTING GUIDE

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. Running the Automated Test Suite

ACDS uses `pytest` for unit, integration, and end-to-end regression testing.

### Running all tests:
```bash
pytest -v
```

### Running specific test modules:
```bash
# Test graph modeling
pytest tests/test_graph.py -v

# Test 5-component Asset Risk formula
pytest tests/test_risk.py -v

# Test attack simulation engine
pytest tests/test_attack_simulation.py -v

# Test honeypot & adaptive feedback
pytest tests/test_honeypot.py tests/test_adaptive_feedback.py -v

# Test defense optimizer & model mutation
pytest tests/test_optimizer.py tests/test_defense_application.py -v

# Test persistence layer
pytest tests/test_persistence.py -v

# Test end-to-end full pipeline
pytest tests/test_end_to_end.py -v
```

---

## 2. Test Coverage Summary

- **`test_graph.py`**: Validates simulated 7-node lab, dynamic scan graphs, and 15-node synthetic SME enterprise networks.
- **`test_risk.py`**: Verifies exact 5-component Asset Risk weights ($40/20/15/15/10$), normalization, and severity classifications.
- **`test_cve.py`**: Validates version splitting, CPE matching, and offline fallback dictionary.
- **`test_attack_simulation.py`**: Verifies BFS attack traversal, step generator, deterministic seed execution, and isolation boundary blocks.
- **`test_honeypot.py` & `test_adaptive_feedback.py`**: Tests honeypot decoy detection, telemetry extraction, and adaptive risk updates.
- **`test_optimizer.py` & `test_defense_application.py`**: Tests greedy knapsack budget allocation, graph mutation, and re-simulation risk reduction.
- **`test_persistence.py`**: Tests SQLite database schema creation, scan persistence, and simulation run records.
- **`test_experiments.py`**: Tests Monte Carlo sweeps, budget sweeps, and CSV/JSON export.
- **`test_reporting.py`**: Tests asset inventory CSV, vulnerability findings CSV, and executive summaries.
- **`test_end_to_end.py`**: End-to-end integration test validating the entire project lifecycle.
