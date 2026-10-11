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

# The dashboard-managed Python receiver owns port 9090 by default. Opt into the
# legacy C collector only when explicitly requested; it replaces that receiver.
if [ "${KERNELSENTINEL_USE_C_COLLECTOR:-0}" = "1" ]; then
    export KERNELSENTINEL_DISABLE_TELEMETRY_RECEIVER=1
fi

echo "Launching Medical AI Agent & Security Dashboard on port 8000..."
python3 -m uvicorn dashboard.app.server:dashboard_app --host 0.0.0.0 --port 8000 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/kernelsentinel_server.pid

# The Python receiver is the default path for ebpf/tracer.py --forward-port 9090.
# The legacy C collector uses the same port and is therefore opt-in.
if [ "${KERNELSENTINEL_USE_C_COLLECTOR:-0}" = "1" ]; then
    if [ -f "ebpf/c-collector/kernelsentinel_collector" ] && [ "$(uname -s)" = "Linux" ]; then
        echo "Launching legacy C collector on port 9090 (Python receiver disabled)..."
        sudo ./ebpf/c-collector/kernelsentinel_collector --port 9090 &
        echo $! > /tmp/kernelsentinel_collector.pid
    else
        echo "KERNELSENTINEL_USE_C_COLLECTOR=1, but compiled C collector is unavailable."
    fi
else
    echo "Dashboard-managed telemetry receiver enabled on 127.0.0.1:9090."
fi

echo "KernelSentinel is running!"
echo "Dashboard UI available at: http://localhost:8000"
