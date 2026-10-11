#!/bin/bash
# =============================================================
# KernelSentinel — Collect Normal Baseline (10 runs)
# Run: sudo ./scripts/run_normal_baseline.sh
# =============================================================

set -e

TOTAL_RUNS=${1:-10}

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   KernelSentinel — Building Baseline     ║"
echo "║   ${TOTAL_RUNS} normal agent runs                   ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check API key
if [ -z "$GEMINI_API_KEY" ]; then
    echo "❌ GEMINI_API_KEY not set"
    echo "   export GEMINI_API_KEY='your-key-here'"
    exit 1
fi

# Check root for eBPF
if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root: sudo ./scripts/run_normal_baseline.sh"
    exit 1
fi

mkdir -p logs baseline_data

echo "[Phase 1] Running ${TOTAL_RUNS} normal agent sessions..."
echo "Each run takes ~20-30 seconds"
echo ""

for i in $(seq 1 $TOTAL_RUNS); do
    echo "─── Normal Run $i/$TOTAL_RUNS ───"
    TRACE_FILE="logs/normal_run_${i}.json"

    # Start tracer in background, capture its PID
    python3 ebpf/tracer.py \
        --all \
        --output "$TRACE_FILE" \
        --duration 25 &
    TRACER_PID=$!

    # Give tracer 2 seconds to load
    sleep 2

    # Run one normal agent prompt
    python3 -c "
import sys, os
sys.path.insert(0, '.')
os.environ['GEMINI_API_KEY'] = os.environ.get('GEMINI_API_KEY', '')
from agent.normal_agent import run_agent, NORMAL_PROMPTS
run_agent(NORMAL_PROMPTS[$((i % 20))], max_turns=3)
" 2>/dev/null &
    AGENT_PID=$!

    # Wait for tracer to complete (25s window)
    wait $TRACER_PID 2>/dev/null || true
    kill $AGENT_PID 2>/dev/null || true

    echo "   ✅ Saved: $TRACE_FILE"
    sleep 1
done

echo ""
echo "[Phase 2] Building baseline profile from ${TOTAL_RUNS} runs..."

python3 algorithm/scorer.py \
    --build-baseline \
    --input logs/normal_run_*.json \
    --baseline baseline_data/baseline.json

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Baseline built successfully!           ║"
echo "║   File: baseline_data/baseline.json      ║"
echo "║                                          ║"
echo "║   Next: sudo ./scripts/run_attack.sh     ║"
echo "╚══════════════════════════════════════════╝"

