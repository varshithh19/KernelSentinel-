#!/usr/bin/env bash

echo "=== Stopping KernelSentinel ==="

if [ -f /tmp/kernelsentinel_server.pid ]; then
    PID=$(cat /tmp/kernelsentinel_server.pid)
    echo "Stopping server (PID $PID)..."
    kill $PID 2>/dev/null || true
    rm -f /tmp/kernelsentinel_server.pid
fi

if [ -f /tmp/kernelsentinel_collector.pid ]; then
    PID=$(cat /tmp/kernelsentinel_collector.pid)
    echo "Stopping C collector (PID $PID)..."
    sudo kill $PID 2>/dev/null || true
    rm -f /tmp/kernelsentinel_collector.pid
fi

echo "All KernelSentinel processes stopped."
