#!/usr/bin/env bash

echo "=== KernelSentinel Environment Diagnostics ==="
echo "Operating System: $(uname -s 2>/dev/null || echo 'Non-Linux')"
echo "Kernel Release:   $(uname -r 2>/dev/null || echo 'N/A')"

if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "Kernel BTF Support: AVAILABLE (/sys/kernel/btf/vmlinux)"
else
    echo "Kernel BTF Support: NOT DETECTED (eBPF will require non-CO-RE fallback)"
fi

echo -n "Python Version:   "
python3 --version 2>/dev/null || python --version 2>/dev/null || echo "Not found"

echo -n "Rustc Version:    "
rustc --version 2>/dev/null || echo "Not found"

echo -n "Cargo Version:    "
cargo --version 2>/dev/null || echo "Not found"

echo -n "GCC Version:      "
gcc --version 2>/dev/null | head -n 1 || echo "Not found"

echo "=== Environment Check Completed ==="
