# ACDS EXPERIMENTATION & RESEARCH BENCHMARK GUIDE

**Project**: Adaptive Cyber Defense System for SMEs (ACDS)

---

## 1. Running Headless Batch Experiments

ACDS includes a programmatic research runner in `acds.experiments.runner` for academic evaluation and paper results generation without launching the web GUI.

### Running a Monte Carlo Attack Sweep:
```python
from acds.experiments.runner import run_monte_carlo_attack_sweep
from acds.experiments.metrics import export_experiment_results_csv, export_experiment_results_json

# Run 50 Monte Carlo simulations across varying seeds
result = run_monte_carlo_attack_sweep(num_runs=50, base_seed=100)

summary = result["summary"]
print(f"Mean Risk: {summary['mean_risk']} ± {summary['std_risk']}")
print(f"Critical Asset Compromise Rate: {summary['critical_compromise_rate_pct']}%")
print(f"Honeypot Detection Rate: {summary['honeypot_detection_rate_pct']}%")

# Export to CSV / JSON
csv_output = export_experiment_results_csv(result["runs"])
json_output = export_experiment_results_json(summary, result["runs"])
```

### Running a Defense Budget Sweep:
```python
from acds.experiments.runner import run_defense_budget_sweep

# Evaluate defense effectiveness across budget constraints (0, 15, 30, 50, 75, 100)
sweep = run_defense_budget_sweep(budgets=[0, 15, 30, 50, 75, 100], seed=42)

for run in sweep:
    print(f"Budget: {run['budget']} | Risk Before: {run['risk_before']} -> After: {run['risk_after']} | Reduction: {run['risk_reduction_pct']}%")
```
