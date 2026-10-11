#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "=== KernelSentinel Results Summary ==="
if [ -f "experiments/reports/evaluation_report.md" ]; then
    cat experiments/reports/evaluation_report.md
else
    echo "No evaluation report found. Run ./scripts/run-tests.sh first."
fi
