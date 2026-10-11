#!/bin/bash
# =============================================================
# KernelSentinel — Run Attack Simulations (5 scenarios)
# Run: sudo ./scripts/run_attack.sh
# =============================================================

set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   KernelSentinel — Attack Simulation     ║"
echo "║   5 Minja/Mistra scenarios               ║"
echo "╚══════════════════════════════════════════╝"
echo ""

if [ -z "$GEMINI_API_KEY" ]; then
    echo "❌ GEMINI_API_KEY not set"; exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root: sudo ./scripts/run_attack.sh"; exit 1
fi

if [ ! -f "baseline_data/baseline.json" ]; then
    echo "❌ Baseline not found. Run run_normal_baseline.sh first."; exit 1
fi

mkdir -p logs

SCENARIOS=(
    "minja_file_read"
    "minja_tool_poison"
    "mistra_shell"
    "mistra_network"
    "combined_max"
)

ATTACK_SCORES=()

echo "[Phase 1] Running 5 attack scenarios..."
echo ""

for i in "${!SCENARIOS[@]}"; do
    SC="${SCENARIOS[$i]}"
    NUM=$((i+1))
    echo "─── Attack $NUM/5: $SC ───"
    TRACE_FILE="logs/attack_run_${NUM}.json"

    # Start tracer
    python3 ebpf/tracer.py \
        --all \
        --output "$TRACE_FILE" \
        --duration 35 &
    TRACER_PID=$!

    sleep 2

    # Run attack agent
    python3 agent/attack_agent.py --scenario "$SC" 2>/dev/null &
    AGENT_PID=$!

    wait $TRACER_PID 2>/dev/null || true
    kill $AGENT_PID 2>/dev/null || true

    echo "   ✅ Saved: $TRACE_FILE"
    sleep 2
done

echo ""
echo "[Phase 2] Scoring all runs through the algorithm..."
echo ""

python3 algorithm/scorer.py \
    --evaluate \
    --baseline baseline_data/baseline.json \
    --normal logs/normal_run_*.json \
    --attack logs/attack_run_*.json \
    --plot

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Attack evaluation complete!            ║"
echo "║                                          ║"
echo "║   Graph saved: logs/risk_score_graph.png ║"
echo "║   Copy graph to local machine:           ║"
echo "║   scp -i key.pem ec2-user@IP:~/         ║"
echo "║   kernelsentinel/logs/risk_score_graph   ║"
echo "║   .png .                                 ║"
echo "╚══════════════════════════════════════════╝"
