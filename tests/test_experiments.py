"""
Unit tests for ACDS Headless Experiments & Monte Carlo Benchmark Suite.
"""

import pytest
from acds.core.graph import build_network
from acds.experiments.runner import run_monte_carlo_attack_sweep, run_defense_budget_sweep
from acds.experiments.metrics import compute_batch_statistics, export_experiment_results_csv, export_experiment_results_json


def test_monte_carlo_attack_sweep():
    G = build_network()
    result = run_monte_carlo_attack_sweep(G, entry_node="User-PC", num_runs=10, base_seed=100)

    assert "summary" in result
    assert "runs" in result
    assert len(result["runs"]) == 10

    summary = result["summary"]
    assert summary["num_runs"] == 10
    assert "mean_risk" in summary
    assert "std_risk" in summary
    assert "critical_compromise_rate_pct" in summary


def test_defense_budget_sweep():
    G = build_network()
    budgets = [0, 20, 50, 100]
    sweep = run_defense_budget_sweep(G, entry_node="User-PC", budgets=budgets, seed=42)

    assert len(sweep) == 4
    assert sweep[0]["budget"] == 0
    assert sweep[-1]["budget"] == 100


def test_export_experiment_results_csv_and_json():
    runs = [
        {"run_id": 1, "seed": 100, "entry_node": "User-PC", "risk_score": 65.0, "blast_details": {"spread": 50.0, "critical_impact": 40.0, "depth": 30.0, "systems_controlled": 3, "critical_assets_reached": 1}, "honeypot_triggered": False},
        {"run_id": 2, "seed": 101, "entry_node": "User-PC", "risk_score": 45.0, "blast_details": {"spread": 30.0, "critical_impact": 20.0, "depth": 20.0, "systems_controlled": 2, "critical_assets_reached": 0}, "honeypot_triggered": True},
    ]
    stats = compute_batch_statistics(runs)

    csv_out = export_experiment_results_csv(runs)
    assert "Run_ID,Seed,Entry_Node" in csv_out
    assert "User-PC" in csv_out

    json_out = export_experiment_results_json(stats, runs)
    assert "summary_statistics" in json_out
    assert "individual_runs" in json_out
