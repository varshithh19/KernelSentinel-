# KernelSentinel Testing & Verification Guide

KernelSentinel provides unit, integration, security, and automated benchmark test suites.

---

## 1. Automated Test Execution

Run all test suites using `pytest`:

```bash
# From the repository root:
python -m pytest medical-agent/tests/ detector/tests/ dashboard/tests/ -v
```

### Verified Test Suites:
1. **`medical-agent/tests/test_medical_agent.py`** (5 tests):
   - Health endpoint & real RSS/CPU reporting.
   - Authorized record retrieval (Dr. Smith -> P101).
   - Unauthorized record access rejection (Dr. Smith -> P102 denied).
   - Direct prompt injection classification & enforcement.
   - MINJA indirect prompt injection detection.
2. **`detector/tests/test_detector.py`** (6 tests):
   - Benign feature extraction.
   - Adversarial telemetry feature extraction.
   - Risk scoring formula & severity thresholds.
   - Empirical baseline tracking and deviation.
   - PID-reuse-safe event correlation pipeline.
   - Safe process containment safeguards (self-protection & PID 1 immunity).
3. **`dashboard/tests/test_dashboard.py`** (5 tests):
   - HTML template rendering.
   - Real-time metrics API response.
   - Attack scenario execution via dashboard API.
   - Containment protection enforcement.

---

## 2. Running Automated Benchmark Experiments

Execute the automated benchmark matrix (5 runs per scenario, 25 total runs):

```bash
python experiments/runner.py
```

Outputs generated:
- `experiments/results/experiment_<timestamp>.json`
- `experiments/results/experiment_<timestamp>.csv`
- `experiments/reports/evaluation_report.md`
