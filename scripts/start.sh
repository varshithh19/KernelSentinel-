#!/usr/bin/env bash

echo "=== Starting KernelSentinel Security Operations Stack ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Export PYTHONPATH
export PYTHONPATH=".:medical-agent:attack-lab"

echo "Launching Medical AI Agent & Security Dashboard on port 8000..."
python3 -m uvicorn dashboard.app.server:dashboard_app --host 0.0.0.0 --port 8000 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/kernelsentinel_server.pid

# Launch C collector if compiled and on Linux
if [ -f "ebpf/c-collector/kernelsentinel_collector" ] && [ "$(uname -s)" = "Linux" ]; then
    echo "Launching privileged eBPF C Collector on port 9090..."
    sudo ./ebpf/c-collector/kernelsentinel_collector --port 9090 &
    echo $! > /tmp/kernelsentinel_collector.pid
fi

echo "KernelSentinel is running!"
echo "Dashboard UI available at: http://localhost:8000"
