#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH=".:medical-agent:attack-lab"

echo "=== Running KernelSentinel Pytest Suites ==="
python3 -m pytest medical-agent/tests/ detector/tests/ dashboard/tests/ -v

echo "=== Running Automated Benchmark Experiment Matrix ==="
python3 experiments/runner.py

echo "=== All Tests and Experiments Passed! ==="
