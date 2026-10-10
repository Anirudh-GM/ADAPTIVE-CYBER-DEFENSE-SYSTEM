# ACDS v2.0 — Testing & Verification Strategy

## 1. Test Suite Summary

The ACDS v2.0 repository contains comprehensive unit, integration, and regression test suites designed to validate every stage of the pipeline without requiring live malicious exploits or external network dependencies.

- **Total Test Files:** 4
- **Total Discovered Tests:** 84
- **Tests Passing:** 84
- **Tests Failing:** 0
- **Tests Skipped:** 0
- **Execution Time:** ~5.0 seconds

---

## 2. Test File Breakdown

| Test File | Description | Test Count | Status |
|---|---|---|---|
| `tests/test_audit_pipeline.py` | Validates multi-adapter discovery, VMware CIDR detection, SSH/HTTP banner parsing, offline CVE fallback, risk formula bounds, single-asset graph creation, multi-asset lateral movement, and defense knapsack optimization. | 12 | **PASSED (12/12)** |
| `tests/test_v4_phases.py` | Validates MITRE ATT&CK edge intelligence, graph risk prioritization, database topology snapshots, defense optimizer v4, historical posture trends, CISA KEV threat intel badges, and non-exploitative simulation distinctions. | 41 | **PASSED (41/41)** |
| `tests/test_dynamic_network_and_asset_identity.py` | Validates dynamic network detection, zero-hardcoding environment resolution, stable `asset_id` invariant across DHCP IP migrations, change detector deltas, decision-based attack simulator, and Level 2 live validation prober. | 18 | **PASSED (18/18)** |
| `tests/test_device_fingerprinting.py` | Validates NetBIOS node query parsing, mDNS service extraction, SSDP UPnP XML parsing, and IEEE OUI / LAA MAC randomization classification. | 13 | **PASSED (13/13)** |

---

## 3. How to Run the Tests

### Prerequisites
- Python 3.10+
- Activated virtual environment (`venv`) with dependencies installed (`pip install -r requirements.txt`).

### Running the Entire Test Suite
Execute the following command from the repository root:
```powershell
python -m unittest discover tests -v
```

### Running Specific Test Modules
```powershell
# Run the audit pipeline suite:
python -m unittest tests/test_audit_pipeline.py -v

# Run the v4 phases suite:
python -m unittest tests/test_v4_phases.py -v

# Run network identity and live validation tests:
python -m unittest tests/test_dynamic_network_and_asset_identity.py -v
```

---

## 4. Test Methodologies & Safety Assurances

1. **Deterministic Test Fixtures:**
   - Network discovery, banner parsing, and CVE correlation tests utilize structured fixtures and mocks.
   - Tests do not require active internet connectivity or access to NIST NVD API servers to pass.

2. **Non-Destructive Testing:**
   - Unit tests do not transmit active network packets to unauthorized subnets.
   - Attack simulation tests verify mathematical graph traversal algorithms without spawning network sockets or executing exploit binaries.
